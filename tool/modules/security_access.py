from can_actions import CanActions, insert_message_length, int_from_str_base
from sys import stdout
import argparse
import time





NRC = {
    0x12: 'subfunctionNotSupported',
    0x13: 'incorrectMessageLengthOrInvalidFormat',
    0x22: 'conditionsNotCorrect',
    0x24: 'requestSequenceError',
    0x31: 'requestOutOfRange',
    0x35: 'invalidKey',
    0x36: 'exceededNumberOfAttempts',
    0x37: 'requiredTimeDelayNotExpired',
}

SA_SUBFUNCS = {
    'requestSeed': range(0x01,0x41,2),
    'sendKey': range(0x02, 0x42, 2)
}

def get_seed(args):
    """
    Requests security access seed for server at src arbitration ID

    :param: args: A namespace containing src and dst
    """
    src = int_from_str_base(args.src)
    dst = int_from_str_base(args.dst)
    def decode_seed(msg):
        if msg.arbitration_id != rcv_arb_id:
            # these are not the droids we're looking for
            return
        import pdb; pdb.set_trace()
        if len(msg.data) >= 2:
            # positive response
            if msg.data[1] == 0x67 and msg.data[2] == SA_SUBFUNCS['requestSeed'][0]:
                print "yay!"
                return msg.data[3:]
            
            # message-queued response
            elif msg.data[1] == 0x7F:
                print "hangout for a sec: response is queued at server"
        else:
            #Error
            pass
        
    with CanActions(arb_id=send_arb_id) as can_wrap:
        print("Requesting Security Access seed")
        can_wrap.send_single_message_with_callback([0x27, SA_SUBFUNCS['requestSeed'][0]], decode_seed)
    
    
def send_key(args):
    """
    Offers security access key to provided arbitration ID

    :param: args: A namespace containing src, dst, and key
    """
    src = int_from_str_base(args.src)
    dst = int_from_str_base(args.dst)
    key = int_from_str_base(args.key)
    
def bruteforce(args):
    """
    Attempts to bruteforce security access key of provided arbitration ID

    :param: args: A namespace containing src, and dst
    """
    src = int_from_str_base(args.src)
    dst = int_from_str_base(args.dst)
    
def bruteforce_security_access(args):
    """
    Scans for diagnostics support by sending session control against different arbitration IDs.

    :param: args: A namespace containing src and dst
    """
    min_id = int_from_str_base(args.min)
    max_id = int_from_str_base(args.max)
    bruteforce_key = int_for_str_base(args.key)

    class SecureKey:
        found = False
    """
    with CanActions() as can_wrap:
        print("Starting diagnostics service discovery")

        def response_analyser_wrapper(arb_id):
            print "\rSending Diagnostic Session Control to 0x{0:04x}".format(arb_id),
            stdout.flush()

            def response_analyser(msg):
                # Catch both ok and negative response
                if len(msg.data) >= 2 and msg.data[1] in [0x50, 0x7F]:
                    SecureKey.found = True
                    print("\nFound diagnostics at arbitration ID 0x{0:04x}, "
                          "reply at 0x{1:04x}".format(arb_id, msg.arbitration_id))
                    if no_stop == False:
                        can_wrap.bruteforce_stop()
            return response_analyser

        def discovery_finished(s):
            if Diagnostics.found:
                print("\n{0}".format(s))
            else:
                print("\nDiagnostics service could not be found: {0}".format(s))

        # Message to bruteforce - [length, session control, default session]
        message = insert_message_length([0x10, 0x01])
        can_wrap.bruteforce_arbitration_id(message, response_analyser_wrapper,
                                           min_id=min_id, max_id=max_id, callback_end=discovery_finished)
    """

def parse_args(args):
    """
    Parser for security-access module arguments.

    :return: Namespace containing action and action-specific arguments
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(prog="cc.py security-access",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="""Security-access module for CaringCaribou""",
                                     epilog="""Example usage:
  cc.py security-access 0x7df 0x7e8""")
    
    subparsers = parser.add_subparsers()

    # Parser for security-access request-seed
    parser_disc = subparsers.add_parser("seed")
    parser_info.add_argument("src", type=str, help="arbitration ID to transmit from")
    parser_info.add_argument("dst", type=str, help="arbitration ID to listen to")
    parser_disc.set_defaults(func=get_seed)

    """
    # Parser for security-access offer-key
    parser_info = subparsers.add_parser("key")
    parser_info.add_argument("src", type=str, help="arbitration ID to transmit from")
    parser_info.add_argument("dst", type=str, help="arbitration ID to listen to")
    parser_disc.add_argument("key", type=str, default=None)
    parser_info.set_defaults(func=send_key)

    # Parser for security-access bruteforce key
    parser_dump = subparsers.add_parser("bruteforce")
    parser_dump.add_argument("src", type=str, help="arbitration ID to transmit from")
    parser_dump.add_argument("dst", type=str, help="arbitration ID to listen to")
    parser_dump.add_argument("-min", type=str, default=None, help="bruteforce key-min")
    parser_dump.add_argument("-max", type=str, default=None, help="bruteforce key-max")
    parser_dump.add_argument("-key", type=str, default=None, help="offer same key for every seed")
    parser_dump.set_defaults(func=bruteforce_security_access)
    """

    args = parser.parse_args(args)
    return args


def module_main(arg_list):
    try:
        args = parse_args(arg_list)
        args.func(args)
    except KeyboardInterrupt:
        print("\n\nTerminated by user")
