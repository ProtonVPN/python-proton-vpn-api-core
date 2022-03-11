Application
------------

.. autoclass:: proton.vpn.core_api.Application
   :members:
   :special-members: __init__
   :undoc-members:

Orchestrators
--------------

Orchestrators delegate the operations on Controllers, which themselves delegate operations to the
components (VPNConnection component, VPNAccount component, VPNServers components, etc)

.. code-block:: ascii

                                         +------+
                                         | View |
                                         +---+--+
                                             |
                                          +--v--+
                                          | App |
                                          +--+--+
                                             |
                                             |
                  +---------------+  +-------v--------+
                  | Session       |  | Connection     |
                  | Orchestrator  <--+ Orchestrator   +---------+------------------+
                  +------+--------+  +--------+-------+         |                  |
                        |                     |                 |                  |
                        |                     |                 |                  |
                        |                     |         +-------v------+     +-----v--------+
                        |                     |         | VPN Servers  |     | User Settings|
           +-------------+                    |         | Orchestrator |     | Orchestrator |
           |             |                    |         +-------+------+     +--------------+
           |             |                    |                 |
   +-------v---+         |                    |                 |
   |Proton VPN |  +------v------+   +---------v-----+   +-------v------+
   |Session    |  | Credentials |   |VPN Connection |   | VPN Servers  |
   |Controller |  | Controller  |   | Controller    |   | Controller   |
   +-----------+  +-------------+   +---------------+   +--------------+


See :

-  :class:`proton.vpn.core_api.controllers.vpnsession.VPNSessionController`
-  :class:`proton.vpn.core_api.controllers.vpnconnection.VPNConnectionController`
-  :class:`proton.vpn.core_api.controllers.vpncredentials.VPNCredentialController`
-  :class:`proton.vpn.core_api.controllers.vpnservers.VPNServersController`

For controllers documentation.

Orchestrators
--------------

.. autoclass:: proton.vpn.core_api.orchestrators.usersettings.UserSettingsOrchestrator
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: proton.vpn.core_api.orchestrators.vpnconnection.VPNConnectionOrchestrator
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: proton.vpn.core_api.orchestrators.vpnserver.VPNServerOrchestrator
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: proton.vpn.core_api.orchestrators.vpnsession.VPNSessionOrchestrator
   :members:
   :special-members: __init__
   :undoc-members:



Controllers
--------------

Controllers implement the high level business logic of the application, ensuring that the VPN
service is in a consistent state.

.. autoclass:: proton.vpn.core_api.controllers.vpnconnection.VPNConnectionController
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: proton.vpn.core_api.controllers.vpncredentials.VPNCredentialController
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: proton.vpn.core_api.controllers.vpnservers.VPNServersController
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: proton.vpn.core_api.controllers.vpnsession.VPNSessionController
   :members:
   :special-members: __init__
   :undoc-members:


User Settings
-------------

.. autoclass:: proton.vpn.core_api.controllers.usersettings.BasicSettings
   :members:
   :special-members: __init__
   :undoc-members:


Persistence
------------

.. autoclass:: proton.vpn.core_api.controllers.usersettings.FilePersistence
   :members:
   :special-members: __init__
   :undoc-members:


Views
------

An abstract view of the user interface.

.. autoclass:: proton.vpn.core_api.views.BaseView
   :members:
   :special-members: __init__
   :undoc-members:


