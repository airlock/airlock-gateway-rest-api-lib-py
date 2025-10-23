#!/usr/bin/env python3
# coding=utf-8

import sys
import logging
import signal

from ..src.rest_api_lib import airlock_gateway_rest_requests_lib as al

module_logger = logging.getLogger(__name__)


def end_sessions(session_list: list[al.GatewaySession]) -> None:
    '''
    Regular termination of sessions
    '''
    for session in session_list:
        al.terminate_session(session)


def terminate_sessions_with_error(session_list: list[al.GatewaySession], message=None) -> None:
    '''
    Terminate sessions and exit with error message
    '''
    if message:
        module_logger.error(message)
    end_sessions(session_list)
    sys.exit(1)


def terminate_session_with_error(session: al.GatewaySession, message=None) -> None:
    '''
    Terminate a single session and exit with error message
    '''
    if message:
        module_logger.error(message)
    al.terminate_session(session)
    sys.exit(1)


def register_cleanup_handlers(session_list: list[al.GatewaySession]) -> None:
    '''
    Register cleanup handler for multiple sessions that terminates all sessions on signal
    '''
    def cleanup(signum, _frame):
        module_logger.warning("Received signal %s, terminating sessions...", signum)
        end_sessions(session_list)
        sys.exit(1)
    for sig in (
        signal.SIGABRT,
        signal.SIGILL,
        signal.SIGINT,
        signal.SIGQUIT,
        signal.SIGSEGV,
        signal.SIGTERM
    ):
        signal.signal(sig, cleanup)


def register_cleanup_handler(gw_session: al.GatewaySession) -> None:
    '''
    Cleanup handler that terminates a single session on signal
    '''
    register_cleanup_handlers([gw_session])


def save_config(session, comment, assume_yes) -> None:
    '''
    Save configuration on target gateway with optional confirmation prompt
    '''
    if not assume_yes:
        ans = input("\nSave the new configuration on target? [y/N] ")
        if ans.lower() != "y":
            module_logger.info("Saving configuration cancelled.")
            return
    if al.save_config(session, comment) is None:
        terminate_session_with_error(session, "Failed to save configuration on target.")
    module_logger.info("Target configuration saved.")


def activate_or_save(session, comment, assume_yes, activate) -> None:
    '''
    Activate or save configuration on target gateway with optional confirmation prompt
    '''
    if activate:
        if not assume_yes:
            ans = input("\nActivate the new configuration on target? [y/N] ")
            if ans.lower() != "y":
                module_logger.info("Activation cancelled. Offer to save configuration instead.")
                return

        if al.activate(session, comment):
            module_logger.info("Target configuration activated successfully.")
            # When activation succeeds the configuration is saved automatically.
            # Therefore, we return here so we don't save it again.
            return
        module_logger.error("Activation failed. Attempt to save the configuration instead.")
        # Try to save the configuration if activation fails
        save_config(session, comment, False)
        return
    save_config(session, comment, assume_yes)


def setup_session(host: str, api_key: str, port: int) -> al.GatewaySession:
    '''
    Sets up a single session given gateway host, api-key, and port,
    and loads the active configuration.

    Returns an al.GatewaySession object
    '''
    session = al.create_session(host, api_key, port)
    if not session:
        terminate_session_with_error(session, f"Could not create session for gateway {host}. Check gateway, port, and API key.")
    register_cleanup_handler(session)
    module_logger.info("Loading active configuration on gateway %s...", host)
    al.load_active_config(session)
    return session


def setup_sessions(host_info_list: list[tuple[str, str, int]]) -> list[al.GatewaySession]:
    '''
    Sets up multiple sessions given a list of (gateway host, api-key, port) tuples
    and loads the active configuration on all gateways.

    Returns a list of al.GatewaySession objects
    '''
    session_list = []
    for host, api_key, port in host_info_list:
        session = setup_session(host, api_key, port)
        session_list.append(session)
    return session_list


def confirm_prompt(prompt, default=False) -> bool:
    '''
    Prompt user for yes/no confirmation with a default value.
    Returns True for yes, False for no.
    '''
    default_str = "Y/n" if default else "y/N"

    while True:
        choice = input(f"{prompt} [{default_str}]: ").strip().lower()

        if not choice:
            result = default
            break
        elif choice in ['y', 'yes']:
            result = True
            break
        elif choice in ['n', 'no']:
            result = False
            break
        else:
            print("Please respond with 'y' or 'n'.")

    return result