#!/usr/bin/env python

import sys
import json
import logging
from typing import Optional, Dict
from PyQt6.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QWidget
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWebSockets import QWebSocketServer, QWebSocket
from PyQt6.QtNetwork import QHostAddress
from PyQt6.QtBluetooth import (
    QBluetoothDeviceDiscoveryAgent,
    QBluetoothDeviceInfo,
    QBluetoothSocket,
    QBluetoothServiceInfo,
    QBluetoothAddress,
    QBluetoothUuid
)

VERSION = "1.0.6-REWRITE"  # Version tracking - complete rewrite, absolutely NO loops

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.info(f"Starting Scratch-Link PyQt6 version {VERSION}")


class EV3BluetoothManager(QObject):
    """Manages Bluetooth connection to LEGO EV3"""

    device_discovered = pyqtSignal(dict)
    connection_status = pyqtSignal(str)
    data_received = pyqtSignal(bytes)
    connected = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.socket: Optional[QBluetoothSocket] = None
        self.discovery_agent: Optional[QBluetoothDeviceDiscoveryAgent] = None
        self.discovered_devices: Dict[str, QBluetoothAddress] = {}
        self.connected_device = None
        self._is_discovering = False
        self._setup_discovery_agent()

    def _setup_discovery_agent(self):
        """Setup or reset the discovery agent"""
        if self.discovery_agent:
            try:
                self.discovery_agent.stop()
                self.discovery_agent.deleteLater()
            except:
                pass

        self.discovery_agent = QBluetoothDeviceDiscoveryAgent()
        self.discovery_agent.deviceDiscovered.connect(self._on_device_discovered)
        self.discovery_agent.finished.connect(self._on_discovery_finished)
        self.discovery_agent.errorOccurred.connect(self._on_discovery_error)

    def start_discovery(self):
        """Start scanning for Bluetooth devices"""
        if self._is_discovering:
            logger.warning("Discovery already in progress")
            return

        logger.info("Starting Bluetooth device discovery...")
        self.connection_status.emit("Scanning for devices...")

        if not self.discovery_agent:
            self._setup_discovery_agent()

        self._is_discovering = True
        try:
            self.discovery_agent.start(QBluetoothDeviceDiscoveryAgent.DiscoveryMethod.ClassicMethod)
        except Exception as e:
            logger.error(f"Failed to start discovery: {e}")
            self.connection_status.emit(f"Failed to start discovery: {e}")
            self._is_discovering = False

    def _on_device_discovered(self, device: QBluetoothDeviceInfo):
        """Handle discovered Bluetooth device"""
        name = device.name()
        address = device.address().toString()

        logger.info(f"Found device: {name} ({address})")

        self.discovered_devices[address] = QBluetoothAddress(address)

        major_class = device.majorDeviceClass()
        minor_class = device.minorDeviceClass()

        logger.debug(f"Device class - Major: {major_class}, Minor: {minor_class}")

        device_info = {
            "name": name if name else "Unknown",
            "rssi": device.rssi(),
            "peripheralId": address,
            "address": address
        }

        if major_class == QBluetoothDeviceInfo.MajorDeviceClass.ToyDevice:
            logger.info(f"Found TOY device (potential EV3): {name}")
            self.device_discovered.emit(device_info)

    def _on_discovery_finished(self):
        """Handle discovery completion"""
        self._is_discovering = False
        logger.info(f"Device discovery finished. Found {len(self.discovered_devices)} devices")
        self.connection_status.emit(f"Discovery complete - found {len(self.discovered_devices)} devices")

    def _on_discovery_error(self, error):
        """Handle discovery errors"""
        self._is_discovering = False
        error_msg = f"Discovery error: {error}"

        if error == QBluetoothDeviceDiscoveryAgent.Error.PoweredOffError:
            error_msg = "Bluetooth is powered off. Please enable Bluetooth and try again."
        elif error == QBluetoothDeviceDiscoveryAgent.Error.InvalidBluetoothAdapterError:
            error_msg = "No Bluetooth adapter found. Please check your Bluetooth hardware."
        elif error == QBluetoothDeviceDiscoveryAgent.Error.UnknownError:
            error_msg = "Unknown Bluetooth error occurred."

        logger.error(error_msg)
        self.connection_status.emit(error_msg)

    def connect_to_device(self, address: str):
        """Connect to EV3 device via Bluetooth"""
        logger.info(f"Attempting to connect to {address}")
        self.connection_status.emit(f"Connecting to {address}...")

        try:
            logger.info(f"Discovered devices: {list(self.discovered_devices.keys())}")

            if address not in self.discovered_devices:
                logger.error(f"Device {address} not found in discovered devices")
                self.connection_status.emit(f"Device not found: {address}")
                return

            bt_address = self.discovered_devices[address]
            logger.info(f"Device found: {bt_address.toString()}")

            if self.socket:
                try:
                    self.socket.abort()
                    self.socket = None
                except Exception as e:
                    logger.error(f"Error cleaning up socket: {e}")

            self.socket = QBluetoothSocket(QBluetoothServiceInfo.Protocol.RfcommProtocol)
            self.socket.connected.connect(self._on_connected)
            self.socket.disconnected.connect(self._on_disconnected)
            self.socket.errorOccurred.connect(self._on_error)
            self.socket.readyRead.connect(self._on_data_ready)
            self.socket.stateChanged.connect(self._on_state_changed)

            spp_uuid = QBluetoothUuid(QBluetoothUuid.ServiceClassUuid.SerialPort)
            logger.info(f"Connecting to {bt_address.toString()} with SPP UUID")

            self.socket.connectToService(bt_address, spp_uuid)
            logger.info("Connection initiated")

        except Exception as e:
            logger.error(f"Exception during connect: {e}", exc_info=True)
            self.connection_status.emit(f"Connection error: {e}")

    def _on_state_changed(self, state):
        """Handle socket state changes"""
        state_names = {
            QBluetoothSocket.SocketState.UnconnectedState: "Unconnected",
            QBluetoothSocket.SocketState.ServiceLookupState: "Service Lookup",
            QBluetoothSocket.SocketState.ConnectingState: "Connecting",
            QBluetoothSocket.SocketState.ConnectedState: "Connected",
            QBluetoothSocket.SocketState.BoundState: "Bound",
            QBluetoothSocket.SocketState.ClosingState: "Closing",
            QBluetoothSocket.SocketState.ListeningState: "Listening"
        }
        state_name = state_names.get(state, f"Unknown({state})")
        logger.info(f"Socket state: {state_name}")
        self.connection_status.emit(f"State: {state_name}")

    def _on_connected(self):
        """Handle successful connection"""
        logger.info("Connected to EV3!")
        self.connection_status.emit("Connected to EV3")
        self.connected.emit()

    def _on_disconnected(self):
        """Handle disconnection"""
        logger.info("Disconnected from EV3")
        self.connection_status.emit("Disconnected")

    def _on_error(self, error):
        """Handle connection errors"""
        error_names = {
            QBluetoothSocket.SocketError.UnknownSocketError: "Unknown Error",
            QBluetoothSocket.SocketError.NoSocketError: "No Error",
            QBluetoothSocket.SocketError.HostNotFoundError: "Host Not Found",
            QBluetoothSocket.SocketError.ServiceNotFoundError: "Service Not Found",
            QBluetoothSocket.SocketError.NetworkError: "Network Error",
            QBluetoothSocket.SocketError.UnsupportedProtocolError: "Unsupported Protocol",
            QBluetoothSocket.SocketError.OperationError: "Operation Error",
        }
        error_name = error_names.get(error, f"Error({error})")
        error_string = self.socket.errorString() if self.socket else "No socket"

        logger.error(f"Bluetooth error: {error_name} - {error_string}")
        self.connection_status.emit(f"Error: {error_name}")

    def _on_data_ready(self):
        """Handle incoming data from EV3"""
        if self.socket:
            data = self.socket.readAll()
            self.data_received.emit(bytes(data))
            logger.debug(f"Received {len(data)} bytes")

    def send_data(self, data: bytes):
        """Send data to EV3"""
        if self.socket and self.socket.state() == QBluetoothSocket.SocketState.ConnectedState:
            written = self.socket.write(data)
            logger.debug(f"Sent {written} bytes")
            return written
        else:
            logger.warning("Cannot send data - socket not connected")
            return 0

    def disconnect(self):
        """Disconnect from device"""
        if self.socket:
            self.socket.disconnectFromService()

    def cleanup(self):
        """Cleanup resources"""
        if self.discovery_agent and self._is_discovering:
            try:
                self.discovery_agent.stop()
            except:
                pass
        self._is_discovering = False

        if self.socket:
            try:
                self.socket.disconnectFromService()
                self.socket.close()
                self.socket.deleteLater()
            except:
                pass
            self.socket = None

        if self.discovery_agent:
            try:
                self.discovery_agent.deleteLater()
            except:
                pass
            self.discovery_agent = None


class WebSocketServerManager(QObject):
    """WebSocket server for Scratch communication using JSON-RPC 2.0"""

    client_connected = pyqtSignal(str)
    client_disconnected = pyqtSignal(str)
    log_message = pyqtSignal(str)

    def __init__(self, host: str = "127.0.0.1", port: int = 20111):
        super().__init__()
        self.host = host
        self.port = port
        self.server: Optional[QWebSocketServer] = None
        self.clients: Dict[str, QWebSocket] = {}
        self.ev3_manager: Optional[EV3BluetoothManager] = None

    def set_ev3_manager(self, manager: EV3BluetoothManager):
        """Set the EV3 Bluetooth manager"""
        self.ev3_manager = manager

    def start(self):
        """Start the WebSocket server"""
        self.server = QWebSocketServer(
            "ScratchLink",
            QWebSocketServer.SslMode.NonSecureMode
        )

        if self.server.listen(QHostAddress(self.host), self.port):
            logger.info(f"WebSocket server started on {self.host}:{self.port}")
            self.log_message.emit(f"WebSocket server running on ws://{self.host}:{self.port}")
            self.server.newConnection.connect(self.on_new_connection)
            return True
        else:
            logger.error(f"Failed to start server: {self.server.errorString()}")
            self.log_message.emit(f"Failed to start server: {self.server.errorString()}")
            return False

    def on_new_connection(self):
        """Handle new WebSocket connection"""
        client = self.server.nextPendingConnection()
        client_id = f"{client.peerAddress().toString()}:{client.peerPort()}"

        self.clients[client_id] = client
        logger.info(f"Client connected: {client_id}")
        self.client_connected.emit(client_id)

        client.textMessageReceived.connect(lambda msg: self.on_message_received(client_id, msg))
        client.disconnected.connect(lambda: self.on_client_disconnected(client_id))

    def on_message_received(self, client_id: str, message: str):
        """Handle incoming message from client"""
        logger.debug(f"Received from {client_id}: {message}")
        self.process_jsonrpc_message(client_id, message)

    def on_client_disconnected(self, client_id: str):
        """Handle client disconnection"""
        if client_id in self.clients:
            logger.info(f"Client disconnected: {client_id}")
            client = self.clients[client_id]
            try:
                client.textMessageReceived.disconnect()
                client.disconnected.disconnect()
            except:
                pass
            del self.clients[client_id]
            self.client_disconnected.emit(client_id)

    def process_jsonrpc_message(self, client_id: str, message: str):
        """Process JSON-RPC 2.0 message from Scratch"""
        try:
            data = json.loads(message)

            method = data.get("method", "")
            params = data.get("params", {})
            msg_id = data.get("id")

            logger.info(f"JSON-RPC method: {method}, params: {params}")

            if method == "discover":
                if self.ev3_manager:
                    self.ev3_manager.start_discovery()
                self.send_jsonrpc_response(client_id, msg_id, None)

            elif method == "connect":
                peripheral_id = params.get("peripheralId", "")
                if self.ev3_manager and peripheral_id:
                    self.ev3_manager.connect_to_device(peripheral_id)
                self.send_jsonrpc_response(client_id, msg_id, None)

            elif method == "send":
                message_data = params.get("message", "")
                encoding = params.get("encoding", "base64")

                if self.ev3_manager and message_data:
                    if encoding == "base64":
                        import base64
                        payload = base64.b64decode(message_data)
                    else:
                        payload = bytes.fromhex(message_data)

                    self.ev3_manager.send_data(payload)

                self.send_jsonrpc_response(client_id, msg_id, len(payload) if message_data else 0)

            elif method == "getServices":
                self.send_jsonrpc_response(client_id, msg_id, [])

            else:
                logger.warning(f"Unknown JSON-RPC method: {method}")
                self.send_jsonrpc_error(client_id, msg_id, -32601, "Method not found")

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            self.send_jsonrpc_error(client_id, None, -32700, "Parse error")
        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            self.send_jsonrpc_error(client_id, msg_id, -32603, str(e))

    def send_jsonrpc_response(self, client_id: str, msg_id, result):
        """Send JSON-RPC 2.0 response"""
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result
        }
        self.send_to_client(client_id, response)

    def send_jsonrpc_error(self, client_id: str, msg_id, code: int, message: str):
        """Send JSON-RPC 2.0 error response"""
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message
            }
        }
        self.send_to_client(client_id, response)

    def send_jsonrpc_notification(self, method: str, params: dict):
        """Send JSON-RPC 2.0 notification to all clients"""
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        self.broadcast(notification)

    def send_to_client(self, client_id: str, message: dict):
        """Send message to specific client"""
        if client_id in self.clients:
            client = self.clients[client_id]
            if client.isValid():
                msg_str = json.dumps(message)
                logger.debug(f"Sending to {client_id}: {msg_str}")
                client.sendTextMessage(msg_str)

    def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        message_str = json.dumps(message)
        for client in self.clients.values():
            if client.isValid():
                client.sendTextMessage(message_str)

    def stop(self):
        """Stop the WebSocket server"""
        for client_id, client in list(self.clients.items()):
            try:
                client.close()
            except:
                pass
        self.clients.clear()

        if self.server:
            self.server.close()
            self.server = None


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scratch-Link PyQt6 (EV3 Edition)")
        self.setGeometry(100, 100, 700, 500)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)

        self.ev3_manager = EV3BluetoothManager()
        self.ev3_manager.device_discovered.connect(self.on_device_discovered)
        self.ev3_manager.connection_status.connect(self.log_message)
        self.ev3_manager.data_received.connect(self.on_ev3_data)
        self.ev3_manager.connected.connect(self.on_ev3_connected)

        self.ws_server = WebSocketServerManager()
        self.ws_server.set_ev3_manager(self.ev3_manager)
        self.ws_server.client_connected.connect(self.on_client_connected)
        self.ws_server.client_disconnected.connect(self.on_client_disconnected)
        self.ws_server.log_message.connect(self.log_message)

        if self.ws_server.start():
            self.log_message("Server started!")
            self.log_message("Waiting for Scratch on ws://127.0.0.1:20111")
        else:
            self.log_message("ERROR: Failed to start server!")

    def log_message(self, message: str):
        """Add message to log display"""
        self.log_display.append(message)

    def on_device_discovered(self, device_info: dict):
        """Handle discovered EV3 device"""
        name = device_info.get("name", "Unknown")
        address = device_info.get("address", "")
        self.log_message(f"Found device: {name} ({address})")
        self.ws_server.send_jsonrpc_notification("didDiscoverPeripheral", device_info)

    def on_client_connected(self, client_id: str):
        """Handle WebSocket client connection"""
        self.log_message(f"Scratch connected: {client_id}")

    def on_client_disconnected(self, client_id: str):
        """Handle WebSocket client disconnection"""
        self.log_message(f"Scratch disconnected: {client_id}")

    def on_ev3_connected(self):
        """Handle EV3 connection"""
        self.log_message("Successfully connected to EV3!")

    def on_ev3_data(self, data: bytes):
        """Handle data received from EV3"""
        self.log_message(f"EV3 data ({len(data)} bytes): {data.hex()}")
        import base64
        self.ws_server.send_jsonrpc_notification("characteristicDidChange", {
            "message": base64.b64encode(data).decode('utf-8'),
            "encoding": "base64"
        })

    def closeEvent(self, event):
        """Handle window close event"""
        self.log_message("Shutting down...")
        self.ws_server.stop()
        if self.ev3_manager:
            self.ev3_manager.cleanup()
        event.accept()


def main():
    app = QApplication(sys.argv)
    sys.excepthook = lambda t, v, tb: logger.error("Uncaught exception", exc_info=(t, v, tb))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
