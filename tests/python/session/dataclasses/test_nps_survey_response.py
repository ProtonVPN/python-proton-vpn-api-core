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
from proton.vpn.session.dataclasses.notifications.nps_survey_response import NPSSurveyResponse


def test_nps_survey_response_clips_score_below_minimum():
    response = NPSSurveyResponse(user_score=NPSSurveyResponse.SCORE_MIN - 1)
    assert response.user_score == NPSSurveyResponse.SCORE_MIN


def test_nps_survey_response_clips_score_above_maximum():
    response = NPSSurveyResponse(user_score=NPSSurveyResponse.SCORE_MAX + 1)
    assert response.user_score == NPSSurveyResponse.SCORE_MAX


def test_nps_survey_response_accepts_score_at_minimum_boundary():
    response = NPSSurveyResponse(user_score=NPSSurveyResponse.SCORE_MIN)
    assert response.user_score == NPSSurveyResponse.SCORE_MIN


def test_nps_survey_response_accepts_score_at_maximum_boundary():
    response = NPSSurveyResponse(user_score=NPSSurveyResponse.SCORE_MAX)
    assert response.user_score == NPSSurveyResponse.SCORE_MAX


def test_nps_survey_response_truncates_comment_to_max_length():
    long_comment = "x" * (NPSSurveyResponse.COMMENT_CHAR_MAX_LENGTH + 50)
    response = NPSSurveyResponse(user_comments=long_comment)
    assert len(response.user_comments) == NPSSurveyResponse.COMMENT_CHAR_MAX_LENGTH


def test_nps_survey_response_does_not_truncate_short_comment():
    short_comment = "x" * (NPSSurveyResponse.COMMENT_CHAR_MAX_LENGTH - 1)
    response = NPSSurveyResponse(user_comments=short_comment)
    assert response.user_comments == short_comment
