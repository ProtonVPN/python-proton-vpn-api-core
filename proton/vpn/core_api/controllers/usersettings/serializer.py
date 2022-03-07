from enum import Enum


class JSONEnumSerializer:
    """JsonEnum Serializer.

    The reason it's called this way is for the way it works. Once any data needs to be
    stored to file, it then converts python objects to JSON friendly format. And, once data
    needs to be loaded from file in JSON format, it then converts the data to known/expected
    python objects (in this case Enum).

    This is recursive based as all keys should be fetched regardless of how deep it is.
    """
    def __init__(self, enum_json_keys):
        """Initializes object.

            :param enum_json_keys: dict with required structured, where keys are derived from Enum and
                values either primitive or complex objects.
            :type enum_json_keys: Enum

        It expected that the self.data variable to contain a dict with the content, either in full
        JSON format or dict format with keys being enums.
        """
        self._enum_json_keys = enum_json_keys
        self.data = {}

    def recursive_parse_to_json_format(self, _data: dict) -> dict:
        """Recursively extract enum values from template.

            :return: json friendly formatted settings dict
            :rtype: dict

        This method will recursively run over the provided template, replacing its enum keys for the
        defined values. It does the same for the values in case they're also enums.
        """
        _dict = {}

        for k, v in _data.items():
            if isinstance(k, Enum):
                _key = k.value
            else:
                _key = k

            if isinstance(v, Enum):
                _val = v.value
            elif isinstance(v, dict):
                _val = self.recursive_parse_to_json_format(v)
            else:
                _val = v

            _dict[_key] = _val

        return _dict

    def recursive_parse_from_json_format(self, data):
        """"Recursively creates a dict based on JSON data.

            :param data: raw JSON data
            :type data: dict
            :return: dict object with convert json to enum for known names
            :rtype: dict
        """
        _dict = {}

        for k, v in data.items():

            if isinstance(v, dict):
                _val = self.recursive_parse_from_json_format(v)
            else:
                _val = v

            try:
                _dict[self._enum_json_keys(k)] = _val
            except ValueError:
                continue

        return _dict

    def recursive_get(self, data, enum):
        """Recursively search and get the content for the matching enum.

            :param data: the dict that contains the settings in memory
            :type data: dict
            :param enum: Optional. If it's not found, the desired default value.
            :type enum: object
            :return: object
            :rtype: enum | str | lst

        All data read form file come from known sources (based on self._enum_json_keys).
        Data is converted from json format to python dict objects where Enum objects are used for keys.
        These "known" values are extracted from the enum_json_keys provided in the constructor.
        Regardless of how deep this enum can be within the tree, as long as key defined in _enum_json_keys
        is found in the file, the value will be found and returned.
        """

        if enum in data:
            return data[enum]

        for k, v in data.items():
            if isinstance(v, dict):
                item = self.recursive_get(v, enum)
                if item is not None:
                    return item

    def recursive_set(self, enum, updated_value, local_data=None):
        """Recurisvely set the desired value to selected enum in memory.

            :param enum: the Enum to be updated
            :type enum: Enum
            :param updated_value: the value to be inserted
            :type updated_value: object
            :param local_data: either contains the entire user setings data or just
                the fragmente that is be recursively searched for.
            :type local_data: object

        Note: Updates the global variable and it only updates the desired value.
        """
        if local_data:
            _internal = local_data
        else:
            _internal = self.data

        if enum in _internal:
            _internal[enum] = updated_value
            return

        for k, v in _internal.items():
            val = None
            if k == enum:
                val = updated_value
            elif isinstance(v, dict):
                val = self.recursive_set(enum, updated_value, v)

            if val:
                _internal[k] = val
