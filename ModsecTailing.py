import collections
import json
import logging
import re
import time
from datetime import datetime

from Tailing import *


# This would start tailing the file
def tail_file(input_file):
    logging.debug('%s:%s Creating the sub-process.', version, module)
    __handler_tail_file__ = subprocess.Popen(['tail', '-F', input_file],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    logging.debug('%s:%s Defining the polling sequence.', version, module)
    poll_sequence = select.poll()
    logging.debug('%s:%s Registering the pooling sequence to the subprocess.', version, module)
    poll_sequence.register(__handler_tail_file__.stdout)
    logging.debug('%s:%s Starting the polling.', version, module)
    while True:
        if poll_sequence.poll(1):
            logging.info('%s:%s Sending the received data for the processing.', version, module)
            process_json(__handler_tail_file__.stdout.readline())
        time.sleep(1)
    __handler_tail_file__.close()


def process_json(input_json):
    logging.debug('%s:%s Data received for the processing.', version, module)
    rule_data = {}

    web_incident = {"index": "incident", "type": "WebIncident"}
    logging.debug('%s:%s Hard-coding the incident specific data.', version, module)
    rule_list = []
    source = {"category": "Web Attack", "protocol": "tcp", "service": "http"}
    logging.debug('%s:%s Hard-coding the category specific data.', version, module)
    raw_Log = {}
    request = {}
    response = {}
    origin = {}
    destination = {}
    severity_count = 0.0

    logging.info('%s:%s Checking the received data and stripping it.', version, module)
    if input_json.strip():
        logging.info('%s:%s Converting the received data to the json.', version, module)
        raw_event = json.loads(unicode(input_json, errors='ignore'))
        audit_messages = None

        logging.debug('%s:%s Checking the {audit_data} attribute in the received data json.', version, module)
        if raw_event.has_key('audit_data'):
            logging.debug('%s:%s Checking the {messages} attribute in the {audit_data}.', version, module)
            if raw_event['audit_data'].has_key('messages'):
                logging.debug('%s:%s Setting the {auditmessage} .', version, module)
                audit_messages = raw_event['audit_data']['messages']
                for message in audit_messages:
                    # TODO have to remove the elements if the match pattern returns empty
                    rule_data = {
                        "regexPattern": (match_patterns(message, matchedPattern)),
                        "ruleFile": (match_patterns(message, filePattern)),
                        "ruleId": (match_patterns(message, idPattern)),
                        "matchedData": (match_patterns(message, dataPattern)),
                        "ruleMessage": (match_patterns(message, msgPattern)),
                        "tags": [str(tag) for tag in (match_patterns(message, tagPattern))]}
                    try:
                        severity_name = str(match_patterns(message, severityPattern))
                        logging.info('%s:%s Severity name for message is: %s.', version, module, severity_name)
                        severity_number = float(severity_message_to_number[severity_name])
                        logging.info('%s:%s Severity number for message is: %s.', version, module, str(severity_number))
                        severity_count = severity_count + severity_number
                    except Exception as es:
                        logging.error('%s:%s Exception in find the severity in the message: %s.', version, module,
                                      es.message)
                    logging.info('%s:%s Appending the ruledata to the rulelist.', version, module)
                    rule_list.append(rule_data)

                severity_score = severity_count / len(audit_messages)
                if severity_score < 1.0:
                    severity_score = 1.0
                elif 1.0 < severity_score <= 1.2:
                    severity_score = 1.2
                elif 1.2 < severity_score <= 1.5:
                    severity_score = 1.5
                elif 1.5 < severity_score <= 2.0:
                    severity_score = 2.0
                elif 2.0 < severity_score <= 2.5:
                    severity_score = 2.5
                elif 2.5 < severity_score <= 3.0:
                    severity_score = 3.0
                elif 3.0 < severity_score <= 4.0:
                    severity_score = 4.0
                elif severity_score > 4.0:
                    severity_score = 5.0
                else:
                    severity_score = 1.0
                logging.info('%s:%s The average Severitycount: %s,  SeverityScore: %s, SeverityNumber: %s.', version,
                             module, str(severity_count), str(severity_score),
                             str(severity_number_to_message[severity_score]))
                source['severityScore'] = severity_score
                source['severityStatus'] = severity_number_to_message[severity_score]
                severity_score = 0.0
                logging.debug('%s:%s End of the messaging loop.', version, module)

                source['ruleList'] = rule_list
        if raw_event.has_key('request'):
            request = raw_event['request']
            raw_Log["request"] = str(convert(request))
            request_line = request['request_line'].split(' ') if raw_event['request'].has_key('request_line') else None
            if len(request_line) > 2:
                source["httpMethod"] = str(request_line[0])
                source["path"] = str(request_line[1])
                source["appLayerProtocol"] = str(request_line[2])

        if raw_event.has_key('response'):
            response = raw_event['response']
            raw_Log["response"] = str(convert(response))
            source["contentLength"] = int(response['headers']['Content-Length']) if response['headers'].has_key(
                'Content-Length') else None
            source["contentType"] = response['headers']['Content-Type'] if response['headers'].has_key(
                'Content-Type') else None

        if raw_event.has_key('transaction'):
            source["srcPort"] = int(raw_event['transaction']['remote_port']) if raw_event['transaction'].has_key(
                'remote_port') else None
            source["dstPort"] = int(raw_event['transaction']['local_port']) if raw_event['transaction'].has_key(
                'local_port') else None
            source["dateTime"] = datetime.strptime(raw_event['transaction']['time'],
                                                   '%d/%b/%Y:%H:%M:%S +0500').isoformat() if raw_event[
                'transaction'].has_key('time') else None
            origin["ip"] = raw_event['transaction']['remote_address'] if raw_event['transaction'].has_key(
                'remote_address') else None
            origin["internal"] = False
            destination["ip"] = raw_event['transaction']['local_address'] if raw_event['transaction'].has_key(
                'local_address') else None
            destination["sensorName"] = get_value_from_configuration('input.sensor_name')

        source["rawLog"] = raw_Log
        source["origin"] = origin
        source["destination"] = destination
        web_incident["source"] = source
        logging.info('%s:%s Writing the web incident to the file.', version, module)
        write_to_file(json.dumps(web_incident),
                      get_out_handler(get_value_from_configuration('output.file_modsec')))


def match_patterns(data, regix):
    match = re.findall(regix, data, re.M | re.I)
    if match:
        return ''.join(match).encode('ascii', 'ignore') if regix is not tagPattern else match
    else:
        logging.warning('%s:%s %s {Does not match the pattern.}', version, module, data)
        return ''


def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data


if __name__ == "__main__":
    version = '{Version 1.0.0:} '
    module = '{Mod-Security Tailer:}'
    matchedPattern = r'Pattern\smatch\s+\"(?P<pattern>.*?)\"'
    filePattern = r'\[file \"(?P<file>.*?)\"\]'
    ruleCategoryPattern = re.compile("\\[file \\\"[A-Za-z_\\/\\-]+[0-9]+_(?P<ruleCategory>.*?).conf\\\"\\]");
    idPattern = '\[id \"(?P<id>[0-9]+)\"\]'
    msgPattern = '\[msg \"(?P<msg>.*?)\"\]'
    dataPattern = "\[data \"(?P<data>.*?)\"\]"
    protocolPattern = re.compile("(?P<protocol>[a-zA-Z]+\\/\\d?\\.\\d?)")
    statusPattern = re.compile("(?P<status>\\d{3}\\s?)")
    tagPattern = '\[tag\s+\"(?P<tag>.*?)\"\]'
    severityPattern = '\[severity\s+\"(?P<severity>.*?)\"\]'

    severity_message_to_number = {"EMERGENCY": 5.0, "ALERT": 4.0, "CRITICAL": 3.0, "ERROR": 2.5, "WARNING": 2.0,
                                  "NOTICE": 1.5,
                                  "INFO": 1.2, "DEBUG": 1.0}
    severity_number_to_message = {5.0: "EMERGENCY", 4.0: "ALERT", 3.0: "CRITICAL", 2.5: "ERROR", 2.0: "WARNING",
                                  1.5: "NOTICE",
                                  1.2: "INFO", 1.0: "DEBUG"}
    logging.basicConfig(filename='logs/modsec.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    if get_value_from_configuration('modsecurity_mode') is not 'off':
        tail_file(get_value_from_configuration('input.file_modsec'))
    else:
        logging.warning('%s : %s Configuration is in [%s] mode.', version, module,
                        get_value_from_configuration('modsecurity_mode'))
