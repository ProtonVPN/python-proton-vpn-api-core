import pytest
import proton.vpn.lib


def test_create_server_status():
    location = {
        "Country" : "FR",
        "Lat" : 35.65,
        "Long" : 139.83
    }
    logicals = {
       "Status" : "kjdkjskfjkjsdfjsdkfjksd",
       "LogicalServers" : [
          {
             "Status" : {
                  "Index" : 0,
                  "Penalty" : 0.5,
                  "Cost" : 1,
              },
             "Domain" : "se-jp-01.protonvpn.net",
             "EntryCountry" : "SE",
             "ExitCountry" : "JP",
             "ID" : "jfskjfsdkfjksdnvknsvskdjv",
             "Location" : {
                "Lat" : 35.65,
                "Long" : 139.83
             },
             "Name" : "SE-JP#1",
             "Servers" : [
                {
                   "Domain" : "node-jp-14.protonvpn.net",
                },
             ]
          }
       ]
    }

    server_status = proton.vpn.lib.ServerStatus(logicals, location)
