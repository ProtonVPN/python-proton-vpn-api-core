import pytest
import json

FEATURES = 86200

ERROR_CODES = [
   # Feature request errors 
   (86200, 'Unknown feature requested'),
   (86201, 'Bad message syntax'),
   (86202, 'Server session doesn\'t match'),
   (86203, 'Server session error (not found)'),
   (86210, 'Netshield level cannot be set - policy'),
   (86211, 'Netshield level cannot be set - system error'),
   (86212, 'Netshield level cannot be set - invalid level'),
   (86215, 'Bouncing cannot be set - policy'),
   (86216, 'Bouncing cannot be set - system error'),
   (86217, 'Bouncing cannot be set - invalid name'),
   (86220, 'Port forwarding cannot be set - policy'),
   (86221, 'Port forwarding cannot be set - system error'),
   (86222, 'Port forwarding cannot be set - invalid syntax'),
   (86223, 'Port forwarding cannot be set - not available on this server'),
   (86225, 'Non randomized nat cannot be set - policy'),
   (86226, 'Non randomized nat cannot be set - system error'),
   (86227, 'Non randomized nat cannot be set - invalid syntax'),
   (86230, 'Split TCP cannot be set - policy'),
   (86231, 'Split TCP cannot be set - system error'),
   (86232, 'Split TCP cannot be set - invalid syntax'),
   (86236, 'Soft Jail cannot be set - system error'),
   (86237, 'Soft Jail cannot be set - invalid syntax'),
   (86240, 'SafeMode cannot be set - policy'),
   (86241, 'SafeMode cannot be set - system error'),
   (86242, 'SafeMode cannot be set - invalid syntax'),
   (86250, 'Conflict between remote bouncing and non-randomized NAT'),
   (86251, 'Conflict between remote bouncing and no split tcp'),
   (86252, 'Conflict between remote bouncing and port forwarding'),
   # Hardjailed
   (86154, 'Bad user behavior'),
]


@pytest.mark.asyncio
async def test_error_codes():
    def responses():
         for code, description in ERROR_CODES:
            yield [
               0,
               {
                     "error": {
                        "code": code,
                        "description": description
                     }
               }
            ]

    from proton.vpn.local_agent import (AgentConnector, PolicyAPIError,
                                        SyntaxAPIError, APIError)
    connection = await AgentConnector().playback(json.dumps(list(responses())))

    for code, _ in ERROR_CODES:
        try:
            await connection.read()
        except PolicyAPIError:
            assert code >= FEATURES and (code % 5 == 0 or code % 5 == 1)
        except SyntaxAPIError:
            assert code >= FEATURES and (code % 5 == 2)
        except APIError:
            assert ((code >= FEATURES and (code % 5 == 3 or code % 5 == 4)) or
                   code < FEATURES)

