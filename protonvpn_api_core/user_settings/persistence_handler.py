import json
import os
from enum import Enum


class SettingsPersistenceHandler:
    """Persists settings to file.

    This class will alway convert known objects to friendly json format
    for easy storage and also does the opposite, when reading from a json
    file it will converty any known json objects to known python objects.

    This is accomplished by knowing which enums to use. If the settings field
    contains something that is unknown the, it will just parse as it is.

    The depth of the settings tree is also not relevant due to recursions, so the settings
    can contain as many items as needed in depth.

    One thing to keep in consideration is that the field can not have exact names, ie: both dns and
    split tunneling can have a status, but the fields can not be both "status" as the algorithm will
    pick only the first match, thus to avoid such occasions it is advised to use dns-status and
    split-tunneling-status.
    """
    def __init__(self, template, fp, enum_template):
        """Initializes object.

            :param template: dict with required structured, where keys are derived from Enum and
                values either primitive or complex objects.
            :type template: Enum
            :param fp: Filepath to settings
            :type fp: str
            :param enum_template: Enum that contains all keywords with their respective values
            :type enum_template: Enum

        This will either create a settings file upon initialization or load from an existing one.
        """
        self._template = template
        self._fp = os.path.join(os.getcwd(), fp)
        self._enum_template = enum_template
        self._data = {}

        if not os.path.isfile(self._fp):
            self._create_settings_file()

        self._load_settings_file()

    def _create_settings_file(self):
        """Creates settings file.

        Uses recursion to parse template into json/human friendly format so that it can be stored on file,
        for persistence purposes.
        """
        json_friendly_format = self._recursive_enum_value_extraction(self._template)

        with open(self._fp, "w+") as f:
            json.dump(json_friendly_format, f, indent=4)

        self._data = self._template

    def _recursive_enum_value_extraction(self, _data: dict) -> dict:
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
                _val = self._recursive_enum_value_extraction(v)
            else:
                _val = v

            _dict[_key] = _val

        return _dict

    def _load_settings_file(self):
        """Load settings from file into memory.

        Internal self._data variable is set to the converted data from file.
        All settings from file are read from known sources. This is then converted
        from json format to python dict objects where Enum objects are used for keys
        and for known values. These "known" values are extracted from the template
        provided in the constructor.
        """
        with open(self._fp, "r") as f:
            data = json.load(f)

        self._data = self._recursive_build_internal_settings(data)

    def _recursive_build_internal_settings(self, data):
        """"Recursively creates a dict based on JSON data.

            :param data: raw JSON data
            :type data: dict
            :return: dict object with convert json to enum for known names
            :rtype: dict
        """
        _dict = {}

        for k, v in data.items():

            if isinstance(v, dict):
                _val = self._recursive_build_internal_settings(v)
            else:
                _val = v

            _dict[self._enum_template(k)] = _val

        return _dict

    def _get(self, enum, _return=None):
        """Getter function to retrieve a specific setting regardless of its position.

            :param enum: the enum type to fetch
            :type enum: Enum
            :param _return: Optional. If it's not found, the desired default value.
            :type _return: object
            :return: object
            :rtype: enum | str | lst

        This method will return anything that this settings holds. It could return a list,
        it could return a string or some other complex object.

        Regardless of how deep this setting can be within the tree, as long as it's declared in the
        template, the value will be found and returned.
        """
        try:
            return self._data[enum]
        except KeyError:
            pass

        try:
            ret_val = self._recursive_get(self._data, enum)
            return ret_val if ret_val else _return
        except: # noqa
            return _return

    def _recursive_get(self, data, enum):
        """Recursively search and get the content for the matching enum.

            :param data: the dict that contains the settings in memory
            :type data: dict
            :param enum: Optional. If it's not found, the desired default value.
            :type enum: object
            :return: object
            :rtype: enum | str | lst
        """
        for k, v in data.items():
            if k.value == enum.value:
                return v
            elif isinstance(v, dict):
                return self._recursive_get(v, enum)

    def _set(self, enum, updated_value):
        """Set values to user settings file.

            :param enum: the Enum to be updated
            :type enum: Enum
            :param updated_value: the value to be inserted
            :type updated_value: object

        It sets the value for the desired enum, which are then stored to file
        for persistence.
        """
        if enum in self._data:
            self._data[enum] = updated_value
        else:
            self._recursive_set(enum, updated_value)

        self._save_to_file()

    def _recursive_set(self, enum, updated_value, local_data=None):
        """Recurisvely set the desired value to selected enum in memory.

            :param enum: the Enum to be updated
            :type enum: Enum
            :param updated_value: the value to be inserted
            :type updated_value: object
            :param local_data: either contains the entire user setings data or just
                the fragmente that is be recursively searched for.
            :type local_data: object

        This update happens in memory, thus it update the self._data variable.

        Note: It only updates the desired value.
        """
        if local_data:
            _internal = local_data
        else:
            _internal = self._data

        for k, v in _internal.items():
            val = None
            if k == enum:
                val = updated_value
            elif isinstance(v, dict):
                val = self._recursive_set(enum, updated_value, v)

            if val:
                _internal[k] = val

    def _save_to_file(self):
        """Persist changes.

        Saves the current user settings to file for persistency.
        """
        json_friendly_format = self._recursive_enum_value_extraction(self._data)
        with open(self._fp, "w+") as f:
            json.dump(json_friendly_format, f, indent=4)
