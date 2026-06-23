"""Constants used throughout ProcmonMCP."""
from datetime import datetime, timezone

# Logging
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'

# Timestamp format used in Procmon XML Time_of_Day
PROCMON_TIMESTAMP_FORMAT = "%H:%M:%S.%f"

# Progress reporting thresholds
PROGRESS_REPORT_INTERVAL = 250000  # Report progress every N events during loading/processing
PROGRESS_REPORT_SECONDS = 5.0  # Also report progress every N seconds

# Base date (epoch) for creating full timestamps from Time_of_Day.
# The parser will advance this date if it detects a midnight rollover.
BASE_DATE = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Known operation strings.
# Procmon emits two distinct lifecycle events: "Process Create" is logged by the
# PARENT (with the parent's PID, path = the child's image), while "Process Start"
# is the process's own start (with its own PID). To find a process's own creation
# time we must consider both, matched against the target PID.
OP_PROCESS_CREATE = "Process Create"
OP_PROCESS_START = "Process Start"
PROCESS_CREATE_OPERATIONS = (OP_PROCESS_CREATE, OP_PROCESS_START)
OP_PROCESS_EXIT = "Process Exit"
NETWORK_OPERATIONS = {"TCP Connect", "TCP Send", "TCP Receive", "UDP Send", "UDP Receive"}

# Midnight rollover detection threshold (seconds)
ROLLOVER_THRESHOLD_SECONDS = 3600

# Input validation limits
MAX_REGEX_LEN = 500
MAX_FILTER_STR_LEN = 1000

# Interner Keys
IK_PROCESS_NAME = "process_name"
IK_OPERATION = "operation"
IK_PATH = "path"
IK_RESULT = "result"
IK_CATEGORY = "category"
IK_STACK_PATH = "stack_path"
IK_STACK_LOCATION = "stack_location"
