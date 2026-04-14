"""
Copyright (c) 2026 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""

from dataclasses import dataclass
from enum import Enum, auto


@dataclass
class NPSSurveyResponse:
    """Content of response to NPS Survey"""
    COMMENT_CHAR_MAX_LENGTH = 250
    SCORE_MIN = 0
    SCORE_MAX = 10

    class ResponseType(Enum):
        """Types of responses to NPS Survey"""
        SUBMIT = auto()
        DISMISS = auto()

    user_score: int = 0
    user_comments: str = ""
    response_type: ResponseType = ResponseType.DISMISS

    def __post_init__(self):
        self.user_score = \
            max(NPSSurveyResponse.SCORE_MIN, min(self.user_score, NPSSurveyResponse.SCORE_MAX))
        self.user_comments = self.user_comments[:NPSSurveyResponse.COMMENT_CHAR_MAX_LENGTH]
