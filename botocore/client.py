
# ClassName -> class object
_SERVICE_CLASS_CACHE = {}


def create_client(service, endpoint):
    class_name = _get_class_name(service)
    op_dict = {}
    for operation in service.operations:
        name = str(operation.py_name)
        op_dict[name] = _create_api_method(name, operation)
    cls = type(class_name, (BaseClient,), op_dict)
    return cls(service, endpoint)


def _create_api_method(name, operation):
    def _wrapper(self, *args, **kwargs):
        response, result = operation.call(self._endpoint, *args,
                                          **kwargs)
        return response, result
    _wrapper.__name__ = str(name)
    # TODO: We'll need to process the html here to get rst syntax.
    _wrapper.__doc__ = operation.documentation
    return _wrapper


def _get_class_name(service):
    return str(service.service_abbreviation.replace(' ', ''))


class BaseClient(object):
    def __init__(self, service, endpoint):
        self._service = service
        self._endpoint = endpoint
