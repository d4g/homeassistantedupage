import logging
import voluptuous as vol
import time
from edupage_api import Edupage
from edupage_api.exceptions import BadCredentialsException, CaptchaException, SecondFactorFailedException
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from.const import CONF_PHPSESSID, CONF_SUBDOMAIN, CONF_STUDENT_ID, CONF_STUDENT_NAME

_LOGGER = logging.getLogger(__name__)

class EdupageConfigFlow(config_entries.ConfigFlow, domain="homeassistantedupage"):
    """Handle a config flow for Edupage."""

    VERSION = 1

    def login(self, api, user_input):
        second_factor = api.login(
            user_input[CONF_USERNAME],
            user_input[CONF_PASSWORD],
            user_input[CONF_SUBDOMAIN],
        )
        if second_factor is not None:
            deadline = time.monotonic() + 60
            while not second_factor.is_confirmed():
                if time.monotonic() > deadline:
                    raise SecondFactorFailedException("2FA confirmation timed out")
                time.sleep(0.5)
            second_factor.finish()

        if not api.is_logged_in:
            raise BadCredentialsException("Wrong username or password")
        _LOGGER.debug("Successfully logged in.")

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            _LOGGER.debug("User submitted config form for subdomain=%s", user_input.get(CONF_SUBDOMAIN))
            api = Edupage()

            try:
                # Login ausführen
                _LOGGER.debug("Starting login process")
                await self.hass.async_add_executor_job(
                    self.login, 
                    api,
                    user_input
                )
                _LOGGER.debug("Login successful")

                # Schülerliste abrufen
                students = await self.hass.async_add_executor_job(api.get_students)
                _LOGGER.debug("Students retrieved: %s", students)

                if not students:
                    errors["base"] = "no_students_found"
                else:
                    # Speichere Benutzer-Eingaben
                    cookies = api.session.cookies.get_dict()
                    phpsess = cookies["PHPSESSID"]
                    user_input[CONF_PHPSESSID] = phpsess
                    self.user_data = user_input
                    self.students = {student.person_id: student.name for student in students}

                    # Weiter zur Schülerauswahl
                    return await self.async_step_select_student()

            except BadCredentialsException as e:
                _LOGGER.warning("Login rejected: %s", e)
                errors["base"] = "invalid_auth"
            except CaptchaException as e:
                _LOGGER.warning("Login blocked by CAPTCHA: %s", e)
                errors["base"] = "captcha_required"
            except SecondFactorFailedException as e:
                _LOGGER.warning("Two-factor confirmation failed: %s", e)
                errors["base"] = "invalid_auth"
            except Exception as e:
                _LOGGER.error("Exception during API call: %s", e)
                errors["base"] = "cannot_connect"

        # Formular anzeigen
        data_schema = vol.Schema({
            vol.Required(CONF_USERNAME): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Required(CONF_SUBDOMAIN): str,
        })

        return self.async_show_form(
            step_id="user", data_schema=data_schema, errors=errors
        )


    async def async_step_select_student(self, user_input=None):
        """Handle the selection of a student."""
        errors = {}

        if user_input is not None:
            student_id = user_input.get("student")
            _LOGGER.info("Selected student ID: %s", student_id)

            # Erstelle den Config-Entry mit allen Daten
            return self.async_create_entry(
                title=f"Edupage ({self.students[student_id]})",
                data={
                    **self.user_data,  # Login-Daten hinzufügen
                    CONF_STUDENT_ID: student_id,
                    CONF_STUDENT_NAME: self.students[student_id],
                },
            )

        # Dropdown-Formular für Schülerauswahl
        student_schema = vol.Schema({
            vol.Required("student"): vol.In(self.students),
        })

        return self.async_show_form(
            step_id="select_student",
            data_schema=student_schema,
            errors=errors
        )
