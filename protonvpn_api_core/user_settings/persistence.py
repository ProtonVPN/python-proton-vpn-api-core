import json
import os
from .serializer import JSONEnumSerializer


class FilePersistence(JSONEnumSerializer):
    """Persists settings to file.

    This class will use a serializer to convert objects to friendly json format
    for easy storage and vice-versa, when reading from a json
    file it will converty json to known python objects based on json keys which should match
    with the keys provided in enum.

    This is accomplished by knowing which enums to use. If the keys do not match,
    then when attempting to fetch a property via _get() it will return the default value instead.

    The depth of the settings tree is also not relevant due to recursions, so the settings
    can contain as many items as needed in depth.

    One thing to keep in consideration is that the field can not have exact names, ie: both dns and
    split tunneling can have a status, but the fields can not be both "status" as the algorithm will
    pick only the first match, thus to avoid such occasions it is advised to use dns-status and
    split-tunneling-status.

    Basic usage:
    ::
        from enum import Enum

        class SettingKeyEnum(Enum):
            KILLSWITCH = "killswitch"
            PROTOCOL = "protocol"
            SPLIT_TUNNELING = "split-tunneling"
            SPLIT_TUNNELING_STATUS = "split-tunneling-status"
            SPLIT_TUNNELING_IPS = "split-tunneling-ips"
            DNS = "dns"
            DNS_STATUS = "dns-status"
            DNS_IPS = "dns-ips"

        settings_template = {
            SettingKeyEnum.KILLSWITCH: 0,
            SettingKeyEnum.PROTOCOL: "tcp",
            SettingKeyEnum.SPLIT_TUNNELING: {
                SettingKeyEnum.SPLIT_TUNNELING_STATUS: 0,
                SettingKeyEnum.SPLIT_TUNNELING_IPS: [],
            },
            SettingKeyEnum.DNS: {
                SettingKeyEnum.DNS_STATUS: 0,
                SettingKeyEnum.DNS_IPS: [],
            },
        }

        import os
        from protonvpn_api_core.user_settings import FilePersistence

        fp = FilePersistence(
            settings_template,
            SettingKeyEnum,
            os.path.join(os.getcwd(), "example.json")
        )

        # Get current value
        print(fp._get(SettingKeyEnum.SPLIT_TUNNELING_IPS))

        # Set to new value
        fp._set(SettingKeyEnum.SPLIT_TUNNELING_IPS, ["192.1.1.2", "191.1.1.1"])

        # Get new value
        print(fp._get(SettingKeyEnum.SPLIT_TUNNELING_IPS))
    """
    def __init__(self, template, enum_with_dict_keys, fp):
        """Initializes object.

            :param template: dict with required structured, where keys are derived from Enum and
                values either primitive or complex objects.
            :type template: Enum
            :param enum_with_dict_keys: Enum that contains all keywords with their respective values
            :type enum_with_dict_keys: Enum
            :param fp: Filepath to settings
            :type fp: str

        This will either create a settings file upon initialization or load from an existing one.
        """
        super().__init__(enum_with_dict_keys)
        self._template = template
        self._fp = os.path.join(os.getcwd(), fp)
        if not os.path.isfile(self._fp):
            self._create_settings_file()

        self._load_settings_file()

    def _create_settings_file(self):
        """Creates settings file.

        Creates the file based on the provided template. After storing it to file it will maintaing it
        in memory.
        """
        json_friendly_format = self.recursive_parse_to_json_format(self._template)

        with open(self._fp, "w+") as f:
            json.dump(json_friendly_format, f, indent=4)

        self.data = self._template

    def _load_settings_file(self):
        """Load settings into memory from file."""
        with open(self._fp, "r") as f:
            data = json.load(f)

        self.data = self.recursive_parse_from_json_format(data)

    def _get(self, enum, _return=None):
        """Getter function to retrieve a specific setting regardless of its position in the tree.

            :param enum: the enum type to fetch
            :type enum: Enum
            :param _return: Optional. If it's not found, the desired default value.
            :type _return: object
            :return: object
            :rtype: enum | str | lst

        This method will return anything that settings hold. It could return a list,
        it could return a string or some other complex object.
        """

        try:
            return self.recursive_get(self.data, enum)
        except: # noqa
            return _return

    def _set(self, enum, updated_value):
        """Set values to user settings file.

            :param enum: the Enum to be updated
            :type enum: Enum
            :param updated_value: the value to be inserted
            :type updated_value: object

        It sets the value for the desired enum, which are then stored to file
        for persistence.
        """

        self.recursive_set(enum, updated_value)
        self._save_to_file()

    def _save_to_file(self):
        """Persist changes.

        Saves the current user settings to file for persistency.
        """
        json_friendly_format = self.recursive_parse_to_json_format(self.data)
        with open(self._fp, "w+") as f:
            json.dump(json_friendly_format, f, indent=4)
