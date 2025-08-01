# --- Imports --- #
import socket
import logging

logger = logging.getLogger("esp32_api")
logging.basicConfig(
    level=logging.DEBUG,  # Log DEBUG and above (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Include timestamp, logger name, etc.
    #filename='_esp32_zephyr_pyapi.log',  # Log to file (omit this to log to console)
    encoding='utf-8'  # Optional: handle non-ASCII characters
)

from  .cmds_pb2 import *

class Esp32API:
    """
    API for communicating with ESP32 via TCP or UDP sockets using protobuf commands.
    """

    def __init__(self, protocol: str, address: str, port: int):
        """
        Initialize connection to ESP32.
        :param protocol: 'tcp' or 'udp'
        :param address: ESP32 IPv4 address as string
        :param port: ESP32 port as integer
        """
        self.protocol = protocol.lower()
        self.addr = (address, port)

        self.sock_send_hndlr = {
            "tcp": self._sock_tcp_send,
            "udp": self._sock_udp_send
        }

    def _sock_tcp_send(self, req_raw: bytearray):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(self.addr)
            s.send(req_raw)
            try:
                return s.recv(1024)
            except socket.timeout:
                logger.warning("Receive timeout")
                return None

    def _sock_udp_send(self, req_raw: bytearray):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.sendto(req_raw, self.addr)
            try:
                res_raw, _ = s.recvfrom(1024)
                return res_raw
            except socket.timeout:
                logger.warning("Receive timeout")
                return None

    def send_cmd(self, req: object, req_id: int):
        """
        Serialize and send protobuf request, then wait for and parse response.
        """
        res = response()
        req.hdr.id = req_id
        req_raw = req.SerializeToString()
        logger.debug(f"--->\n{req}")
        res_raw = self.sock_send_hndlr[self.protocol](req_raw)
        try:
            res.ParseFromString(res_raw)
            logger.debug(f"<---\n{res}")
        except Exception as err:
            logger.error(f"Error parsing response: {err}")
            return None

        if res.hdr.ret != OK:
            logger.error(f"Command failed! (ret: {res.hdr.ret}) {res.hdr.err_msg}")

        return res

    # Example API methods for high-level usage; you can extend these as needed:
    def version_get(self) -> dict:
        version = {
            'version': 0,
            'branch': '',
            'sha1': '',
            'commit_date': ''
        }

        req = request()
        res = self.send_cmd(req, VERSION_GET)
        if res is not None:
            if res.hdr.ret == OK:
                version['version'] = res.version_get.version
                version['branch'] = res.version_get.branch
                version['sha1'] = res.version_get.sha1
                version['commit_date'] = res.version_get.commit_date
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")

        return version

    def adc_channels_get(self) -> int:
        adc_chs = 0

        req = request()
        res = self.send_cmd(req, ADC_CHS_GET)
        if res is not None:
            if res.hdr.ret == OK:
                adc_chs = res.adc_chs_get.adc_chs
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")

        return adc_chs

    def adc_channel_read(self, ch: int) -> int:
        adc_val = 0
        req = request()
        req.adc_ch_read.ch = ch
        res = self.send_cmd(req, ADC_CH_READ)
        if res is not None:
            if res.hdr.ret == OK:
                adc_val = res.adc_ch_read.val
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")

        return adc_val

    def pwm_chs_get(self) -> int:
        pwm_chs = 0
        req = request()
        res = self.send_cmd(req, PWM_CHS_GET)
        if res is not None:
            if res.hdr.ret == OK:
                pwm_chs = res.pwm_chs_get.pwm_chs
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")

        return pwm_chs

    def pwm_get(self, ch: int) -> dict:
        adc_val = 0
        req = request()
        req.adc_ch_read.ch = ch
        res = self.send_cmd(req, PWM_CH_GET)
        if res is not None:
            if res.hdr.ret == OK:
                adc_val = res.adc_ch_read.val
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")

        return adc_val

    def pwm_set(self, ch: int, period: int, pulse: int) -> bool:
        success = True

        req = request()
        req.pwm_ch_set.ch = ch
        req.pwm_ch_set.period = period
        req.pwm_ch_set.pulse = pulse
        res = self.send_cmd(req, PWM_CH_SET)
        if res is not None:
            if res.hdr.ret != OK:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                success = False

        return success

    def pwm_periods_get(self) -> dict:
        pwm_periods_interval = {
            'min': 0,
            'max': 0
        }

        req = request()
        res = self.send_cmd(req, PWM_PERIOD_INTERVAL_GET)
        if res is not None:
            if res.hdr.ret == OK:
                pwm_periods_interval['min'] = res.pwm_periods_get.period_min
                pwm_periods_interval['max'] = res.pwm_periods_get.period_min
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")

        return pwm_periods_interval
