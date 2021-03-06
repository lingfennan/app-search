# All the Critical cues for detecting Bluetooth, NFC, WifiP2P usage etc. #
Bluetooth:
- Permission
	android.permission.BLUETOOTH_ADMIN
		Allows applications to discover and pair bluetooth devices
	android.permission.BLUETOOTH
		Allows applications to connect to paired bluetooth devices
	android.permission.BLUETOOTH_PRIVILEGED
		Allows applications to pair bluetooth devices without user interaction, and to
		allow or disallow phonebook access or message access. This is not available to
		third party applications.

- Methods
	android.bluetooth.BluetoothAdapter
		getBondedDevices
		startDiscovery
		listenUsingRfcommWithServiceRecord
		startLeScan
	BluetoothSocket
		connect
	BluetoothServerSocket
		accept


Socket:
[ssl server socket](http://www.programcreek.com/java-api-examples/javax.net.ssl.SSLSocketFactory)
[java ssl](http://stilius.net/java/java_ssl.php)
- Permission
	android.permission.INTERNET

- Methods
	java.net.InetSocketAddress
		<init>
	java.net.ServerSocket
		<init>
		accept
	java.net.DatagramPacket
		<init>
		receive
	javax.net.ssl.SSLServerSocket
		<init>
		accept

[java.nio socket](http://tutorials.jenkov.com/java-nio/server-socket-channel.html)
[There is no SSLServerSocketChannel](http://docs.oracle.com/javase/6/docs/technotes/guides/security/jsse/JSSERefGuide.html#SSLENG)
- Permission
    android.permission.INTERNET

- Methods
    java.nio.channels.ServerSocketChannel
        <init>
        accept
    java.nio.channels.DatagramChannel
        <init>
        receive


NFC: host-based card emulation. This allows any Android application to emulate a card and talk directly to the NFC reader
- Permission
	android.permission.NFC
		Allows applications to perform I/O operations over NFC.
	android.permission.BIND_NFC_SERVICE
		Must be required by a HostApduService or OffHostApduService to ensure that only
		the system can bind to it.
		Protection level: signature

- Methods
	NdefRecord
		<init>
	android.nfc.NfcAdapter
		enableForegroundNdefPush
		setNdefPushMessage or setNdefPushMessageCallback
	HostApduService
		processCommandApdu
	OffHostApduService


[Wifi P2P](http://developer.android.com/intl/zh-cn/guide/topics/connectivity/wifip2p.html)
- Permission
	android.permission.ACCESS_WIFI_STATE
	android.permission.CHANGE_WIFI_STATE
	android.permission.INTERNET

- Methods
	android.net.wifi.p2p.WifiP2pManager
		initialize
		discoverPeers or discoverServices
		connect


# Description of all the config files.
ctl-and-comm.config
- tcp/udp socket, bluetooth, nfc and wifi manager, the very first version, I think not useful anymore.

sock-server-client.config
- the tcp/udp socket (inet) and unix socket

wifi-ble-nfc.config
- the wifip2p, bluetooth and nfc usage config

general-sock-usage.config
- the latest version of socket communication, including tcp/udp socket (inet), unix socket, nfc socket, bluetooth socket (wifi p2p is recorded, but not useful)
- this file is basically the union of sock-server-client.config and wifi-ble-nfc.config

test-impl-using-\*.config
- the configurations used tests

hello-world.config / port-backdoor.config
- demo config, not useful at all
