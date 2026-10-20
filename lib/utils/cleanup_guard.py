"""reauthx: keep impacket's post-dump cleanup from printing a thread traceback.

The SAM/LSA dump runs over the reflected session. When it finishes, impacket's
secretsdump __restore() stops the RemoteRegistry service it started; on some
hosts that STOP returns an SCMR error (e.g. 0x41b ERROR_DEPENDENT_SERVICES_RUNNING).
The secretsdump.py CLI wraps its dump in try/except and logs this on one line;
the relay runs the dump in an attack thread, so the same exception would print as
a full "Exception in thread" traceback instead. We log it on one line too, with
the raw error text so the operator can judge it.

This is impacket cleanup behaviour (vanilla secretsdump raises the same), not
specific to the bypass, so the line carries no reauthx tag. Only exceptions that
come through secretsdump's cleanup path are handled; anything else is passed to
the previous hook untouched. Installed only when --reauth-bypass is used, so
vanilla krbrelayx behaviour is unchanged.
"""
import logging
import sys
import threading
import traceback

# secretsdump functions that only run during cleanup, after the dump itself
_CLEANUP_FUNCS = ('__restore', '_RemoteOperations__restore', 'finish', 'cleanup')


def _is_secretsdump_cleanup(tb):
    for frame, _ in traceback.walk_tb(tb):
        code = frame.f_code
        if 'secretsdump.py' in code.co_filename and code.co_name in _CLEANUP_FUNCS:
            return True
    return False


def install():
    prev_thread_hook = threading.excepthook
    prev_unraisable_hook = sys.unraisablehook

    def thread_hook(args):
        if args.exc_traceback is not None and _is_secretsdump_cleanup(args.exc_traceback):
            logging.error('secretsdump cleanup error: %s', args.exc_value)
            return
        prev_thread_hook(args)

    def unraisable_hook(args):
        # impacket #1634: at interpreter shutdown Cryptodome is already torn down,
        # so Registry.__del__ -> AES_CMAC raises KeyError. Fires only during teardown.
        if isinstance(args.exc_value, KeyError) and 'Cryptodome' in str(args.exc_value):
            return
        prev_unraisable_hook(args)

    threading.excepthook = thread_hook
    sys.unraisablehook = unraisable_hook
