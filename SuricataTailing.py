import json
import logging
import time

from Tailing import *


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
            line = __handler_tail_file__.stdout.readline()
            if line.isspace():
                logging.warning('%s:%s Line is empty.', version, module)
            else:
                process_json(line)
        time.sleep(1)
    __handler_tail_file__.close()


def process_json(input_json):
    try:
        logging.debug('%s:%s %s received for the processing.', input_json, version, module)
        raw_event = json.loads(input_json)
        network_incident = None
        signature_data = None
        source = None
        payload = None

        logging.debug('%s:%s Finding alert in the received json.', version, module)
        if raw_event.has_key('alert'):
            if raw_event['alert'].has_key('signature'):
                logging.debug('%s:%s Found signature in the alert.', version, module)
                logging.info('%s:%s Setting the signature data in the incident.', version, module)
                signature_data = {'severityScore': raw_event['alert']['severity'],
                                  'signatureClass': raw_event['alert']['category'],
                                  'signature': raw_event['alert']['signature']}
            else:
                logging.warning('%s:%s Dropping the {%s} to the because its not contains the signature.', version,
                                module,
                                raw_event['alert'])
                write_to_file(json.dumps(raw_event['alert']),
                              get_drop_handler(get_value_from_configuration('out.drop_suricata')))
        else:
            logging.debug('%s:%s Setting the severity score of the event because it doesn`t contains alert', version,
                          module)
            signature_data = {'severityScore': 1}
            logging.warning('%s:%s Dropping the {%s} to the because its not contains the alert.', version, module,
                            raw_event)
            write_to_file(json.dumps(raw_event), get_drop_handler(get_value_from_configuration('output.drop_suricata')))

        if raw_event.has_key('payload_printable'):
            logging.info('%s:%s Setting the payload of the incident both encoded and decoded.', version, module)
            payload = {'encoded': raw_event['payload'], 'decoded': raw_event['payload_printable']}
        if raw_event.has_key('dest_port'):
            if raw_event['dest_port'] in get_value_from_configuration('teye_port'):
                logging.info('%s:%s The incident is misc incident to adding it as a probing.', version, module)
                network_incident = {'index': 'incident', 'type': 'MiscIncident', 'source': None}
                source = {'dateTime': raw_event['timestamp'],
                          'srcPort': raw_event['src_port'], 'dstPort': raw_event['dest_port'],
                          'protocol': raw_event['proto'], 'category': 'Reconnaissance',
                          'origin': {
                              'ip': raw_event['src_ip'], 'internal': None
                          },
                          'destination': {
                              'ip': raw_event['dest_ip'],
                              'sensorName': get_value_from_configuration('input.sensor_name')
                          },
                          'payload': None
                          }
            else:
                logging.info('%s:%s The incident is meta incident moving it to meta index.', version, module)
                network_incident = {'index': 'meta', 'type': 'NetworkInfo', 'source': None}
                source = {'dateTime': raw_event['timestamp'],
                          'srcPort': raw_event['src_port'], 'dstPort': raw_event['dest_port'],
                          'protocol': raw_event['proto'],
                          'origin': raw_event['src_ip'],
                          'destination': raw_event['dest_ip'],
                          'payload': None
                          }

            source.update(signature_data)
            if payload is not None:
                source.update(payload)
            network_incident['source'] = source
            logging.info('%s:%s Writing the event to the out file.', version, module)
            write_to_file(json.dumps(network_incident),
                          get_out_handler(get_value_from_configuration('output.file_suricata')))
        else:
            logging.warning('%s:%s Dropping the {%s} to the because its not contains the dest port.', version, module,
                            raw_event)
            write_to_file(json.dumps(raw_event), get_drop_handler(get_value_from_configuration('output.drop_suricata')))

    except Exception as e:
        logging.error('%s:%s There is an error while processing json. %s', version, module, e)


if __name__ == "__main__":

    version = '{Version 1.0.2:} '
    module = '{Suricata Tailer:}'
    logging.basicConfig(filename='logs/suricata.log', level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    if get_value_from_configuration('suricata_mode') is not 'off':
        tail_file(get_value_from_configuration('input.file_suricata'))
    else:
        logging.error('Suricata is in: ', get_value_from_configuration('suricata_mode'))
