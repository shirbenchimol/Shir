# Network Configuration

SERVER_IP = '0.0.0.0'
PORT = 33333
BUFSIZ = 1024 * 10
SERVER_ADDR = (SERVER_IP, PORT)
UDP_PORT = 33334
DISCOVERY_MSG = "GCI_DISCOVER_SERVER"

# GUI Configuration

# הוספתי את PPID כדי שאני אוכל לבנות את "עץ המשפחה" של התהליכים
AFK_COLUMNS = ("PID", "PPID", "Name", "Create Time", "CPU Usage (%)", "Memory Usage (MB)", "Status")
NET_COLUMNS = ("PID", "Process Name", "Local Address", "Remote Address", "Status")
PERSISTENCE_COLUMNS = ("Registry Location", "Program Name", "Execution Path")
ANOMALY_COLUMNS = ("PID", "Process Name", "Severity", "Reason", "Execution Path")
