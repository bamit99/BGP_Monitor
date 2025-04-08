# utils/notification_manager.py
import smtplib
import ssl
import socket # Import socket for gaierror
from email.message import EmailMessage
import logging
from utils.config_manager import config_manager # Use shared instance

logger = logging.getLogger(__name__)

# Define severity levels for comparison
SEVERITY_LEVELS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

def send_email_alert(alert_details: dict):
    """
    Sends an email notification for a BGP security alert based on configuration.

    Args:
        alert_details (dict): A dictionary containing the alert information,
                              including 'severity', 'prefix', 'reasons', etc.
    """
    try:
        # Load configuration safely
        app_settings = config_manager.load_app_settings()
        email_config = app_settings.get("notifications", {}).get("email", {})

        # Check if email notifications are enabled
        if not email_config.get("enabled", False):
            # logger.debug("Email notifications are disabled in config.")
            return

        # Check severity threshold
        min_severity_str = email_config.get("min_email_severity", "MEDIUM").upper()
        alert_severity_str = alert_details.get("severity", "LOW").upper()

        min_level = SEVERITY_LEVELS.get(min_severity_str, 1) # Default to MEDIUM level
        alert_level = SEVERITY_LEVELS.get(alert_severity_str, 0) # Default to LOW level

        if alert_level < min_level:
            logger.debug(f"Alert severity {alert_severity_str} below threshold {min_severity_str}. Skipping email.")
            return

        # Get SMTP details from config
        smtp_host = email_config.get("smtp_host")
        smtp_port = email_config.get("smtp_port", 587) # Default to 587 for TLS
        smtp_user = email_config.get("smtp_user")
        smtp_password = email_config.get("smtp_password")
        use_tls = email_config.get("use_tls", True)
        sender_email = email_config.get("sender_email")
        recipient_emails = email_config.get("recipient_emails", [])

        # Validate essential config
        if not smtp_host or not sender_email or not recipient_emails:
            logger.error("Email notification failed: Missing essential SMTP configuration (host, sender, recipients).")
            return

        # Construct Email Message
        msg = EmailMessage()
        subject = f"BGP Alert [{alert_severity_str}]: {alert_details.get('prefix', 'N/A')}"
        body_lines = [
            f"BGP Monitor detected a potential security event:",
            f"-------------------------------------------------",
            f"Timestamp: {alert_details.get('timestamp', 'N/A')}",
            f"Severity: {alert_severity_str}",
            f"Prefix: {alert_details.get('prefix', 'N/A')}",
            f"AS Path: {alert_details.get('as_path', 'N/A')}",
            f"Origin AS: {alert_details.get('origin_as', 'N/A')}",
            f"Peer AS: {alert_details.get('peer_asn', 'N/A')}",
            f"Reasons:",
        ]
        for reason in alert_details.get('reasons', []):
            body_lines.append(f"  - {reason}")
        body_lines.append(f"-------------------------------------------------")
        body = "\n".join(body_lines)

        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = ", ".join(recipient_emails) # Comma-separated string for header
        msg.set_content(body)

        # Send Email
        context = ssl.create_default_context() if use_tls else None
        server = None
        try:
            logger.info(f"Connecting to SMTP server: {smtp_host}:{smtp_port}")
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10) # Add timeout
            if use_tls:
                # server.set_debuglevel(1) # Uncomment for SMTP debugging
                server.ehlo() # Identify ourselves to the server
                server.starttls(context=context)
                server.ehlo() # Re-identify ourselves after TLS
                logger.debug("TLS connection established.")
            # Login only if username is provided
            if smtp_user:
                logger.debug(f"Attempting SMTP login as {smtp_user}")
                server.login(smtp_user, smtp_password)
                logger.debug("SMTP login successful.")

            logger.info(f"Sending alert email to: {', '.join(recipient_emails)}")
            server.send_message(msg)
            logger.info("Alert email sent successfully.")

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication failed for user {smtp_user}: {e}")
        except smtplib.SMTPException as e:
            logger.error(f"SMTP Error sending email: {e}")
        except ConnectionRefusedError:
             logger.error(f"SMTP Connection refused by server {smtp_host}:{smtp_port}.")
        except socket.gaierror:
             logger.error(f"SMTP Hostname resolution failed for {smtp_host}.")
        except Exception as e:
            logger.error(f"Unexpected error sending email: {e}", exc_info=True) # Log full traceback
        finally:
            if server:
                try:
                    server.quit()
                    logger.debug("SMTP connection closed.")
                except:
                    pass # Ignore errors during quit

    except Exception as e:
        logger.error(f"Error in send_email_alert function setup: {e}", exc_info=True)

# Example usage (for testing purposes, remove later)
# if __name__ == '__main__':
#     logging.basicConfig(level=logging.DEBUG)
#     test_alert = {
#         'timestamp': '2023-10-27T10:00:00Z',
#         'severity': 'HIGH',
#         'prefix': '192.0.2.0/24',
#         'as_path': '65001,65002,65003',
#         'origin_as': 65003,
#         'peer_asn': 65000,
#         'reasons': ['RPKI Invalid', 'Origin change from AS65004 to AS65003']
#     }
#     # Make sure config/app_settings.json has valid SMTP details and enabled=true
#     send_email_alert(test_alert)
