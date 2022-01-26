from .country_codes import country_codes


class Country:
    """Country Class.
    Use it to get country name and check if country codes exist.

    Exposes method:
        _get_country_name(country_code: String)
        _ensure_country_exists(country_code: String)

    Description:
    _get_country_name()
        Gets a country name based on the provided country code in
        string (ISO) format.
    _ensure_country_exists()
        Ensures that a given country code exists.
    """

    def get_dict_with_country_servername(self, server_list, user_tier=False):
        """Generate dict with {country:[servername]}.

        Args:
            server_list (list)
            tier (int)
        Returns:
            dict: country_code: [servername]
                ie {PT: [PT#5, PT#8]}
        """
        countries = {}
        for server in server_list:
            if user_tier is not False and int(server.tier) <= int(user_tier):
                country = self.get_country_name(server.exit_country)
            elif isinstance(user_tier, bool) and not user_tier:
                country = self.get_country_name(server.exit_country)
            else:
                continue

            if country not in countries.keys():
                countries[country] = []
            countries[country].append(server.name)

        return countries

    def get_dict_with_country_code_servername(self, server_list):
        """Generate dict with {country:[servername]}.

        Args:
            server_list (list)
        Returns:
            dict: country_code: [servername]
                ie {PT: [PT#5, PT#8]}
        """
        countries = {}
        for server in server_list:
            if countries.get(server.exit_country):
                countries[server.exit_country].append(server.name)
            else:
                countries[server.exit_country] = []
                countries[server.exit_country].append(server.name)

        return countries

    def get_country_name(self, country_code):
        """Get country name of a given country code.

        Args:
            country_code (string): ISO format
        """
        return self.extract_country_name(country_code)

    def ensure_country_code_exists(self, country_code):
        """Checks if given country code exists.

        Args:
            country_code (string): ISO format

        Returns:
            bool
        """
        if not self.extract_country_name(country_code):
            raise ValueError(
                "The provided country code {} does not exist.".format(
                    country_code
                )
            )

    def extract_country_name(self, country_code):
        """Extract country name based on specified code.

        Args:
            code (string): country code [PT|SE|CH]

        Returns:
            string:
                country name if found, else returns country code
        """
        return country_codes.get(country_code, country_code)
    
    @property
    def country_codes(self):
        return country_codes
