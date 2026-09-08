class ScannerError(Exception):
    """Base class for all scanner errors that should be shown to the operator,
    not surfaced as a raw traceback."""


class AdapterError(ScannerError):
    pass
