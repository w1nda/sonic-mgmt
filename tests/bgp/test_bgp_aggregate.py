import pytest
import logging
import json
from tests.common.gcu_utils import generate_tmpfile, create_checkpoint, \
    apply_patch, expect_op_success, delete_tmpfile, \
    rollback_or_reload, delete_checkpoint

CONFIG_DB_NAME = "CONFIG_DB"
STATE_DB_NAME = "STATE_DB"
BGP_AGGREGATE_ADDRESS_TABLE_NAME = "BGP_AGGREGATE_ADDRESS"
BBR_REQUIRED_KEY = "bbr-required"
AS_SET_KEY = "as-set"
SUMMARY_ONLY_KEY = "summary-only"
AGGREGATE_ADDRESS_PREFIX_LIST_KEY = "aggregate-address-prefix-list"
CONTRIBUTING_ADDRESS_PREFIX_LIST_KEY = "contributing-address-prefix-list"
COMMON_TRUE_STRING = "true"
COMMON_FALSE_STRING = "false"
COMMON_EMPTY_STRING = ""
ADDRESS_STATE_KEY = "state"
ADDRESS_ACTIVE_STATE = "active"
ADDRESS_INACTIVE_STATE = "inactive"
BBR_DISABLED_STATE = "disabled"
BBR_ENABLED_STATE = "enabled"


pytestmark = [
    pytest.mark.topology('m0')
]

logger = logging.getLogger(__name__)


class AggregateAddress:
    def __init__(self, prefix, bbr_required=False, as_set=False, summary_only=False,
                 aggregate_address_prefix_list="", contributing_address_prefix_list="", state=ADDRESS_INACTIVE_STATE):
        self.prefix = prefix
        self.bbr_required = bbr_required
        self.as_set = as_set
        self.summary_only = summary_only
        self.aggregate_address_prefix_list = aggregate_address_prefix_list
        self.contributing_address_prefix_list = contributing_address_prefix_list
        self.state = state
    
    def __eq__(self, other):
        return (self.prefix == other.prefix and
                self.bbr_required == other.bbr_required and
                self.as_set == other.as_set and
                self.summary_only == other.summary_only and
                self.aggregate_address_prefix_list == other.aggregate_address_prefix_list and
                self.contributing_address_prefix_list == other.contributing_address_prefix_list and
                self.state == other.state)
    
    def __str__(self):
        return "AggregateAddress(prefix={}, bbr_required={}, as_set={}, summary_only={}, "\
               "aggregate_address_prefix_list={}, contributing_address_prefix_list={}, state={})".format(
                   self.prefix, self.bbr_required, self.as_set, self.summary_only,
                   self.aggregate_address_prefix_list, self.contributing_address_prefix_list, self.state)


def gcu_template(duthost, json_patch):
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    check_point = "bgp_aggregate_test"
    try:
        create_checkpoint(duthost, check_point)
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost, check_point)
        delete_checkpoint(duthost, check_point)


def format_prefix(prefix):
    return prefix.replace("/", "~")


@pytest.fixture(scope='module', autouse=True)
def add_aggregate(duthost, address):
    json_patch = [
        {
            "op": "add",
            "path": "/%s/%s" % (BGP_AGGREGATE_ADDRESS_TABLE_NAME, format_prefix(address.prefix)),
            "value": {
                BBR_REQUIRED_KEY: COMMON_TRUE_STRING if address.bbr_required else COMMON_FALSE_STRING,
                AS_SET_KEY: COMMON_TRUE_STRING if address.as_set else COMMON_FALSE_STRING,
                SUMMARY_ONLY_KEY: COMMON_TRUE_STRING if address.summary_only else COMMON_FALSE_STRING,
                AGGREGATE_ADDRESS_PREFIX_LIST_KEY: address.aggregate_address_prefix_list,
                CONTRIBUTING_ADDRESS_PREFIX_LIST_KEY: address.contributing_address_prefix_list
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def check_aggregate(duthost):
    # 1. Query config DB to get aggregate config
    addresses_in_config = get_address_from_config_db(duthost)
    # 2. Query state DB to get aggregate state
    addresses_state = get_address_from_state_db(duthost)
    # 3. Query address from running config
    addresses_running = get_address_from_running_config(duthost)
    # 4. Get BBR state
    cmd = "sudo sonic-db-cli {} HGETALL BGP_BBR".format(CONFIG_DB_NAME)
    bbr_state = BBR_DISABLED_STATE
    if BBR_ENABLED_STATE in duthost.shell(cmd)['stdout']:
        bbr_state = BBR_ENABLED_STATE
    # 5. Validate address
    validate_address(addresses_in_config, addresses_state, addresses_running, bbr_state)


def get_address_from_config_db(duthost):
    addresses = []
    keys_cmd = "sudo sonic-db-cli {} KEYS {}*".format(CONFIG_DB_NAME, BGP_AGGREGATE_ADDRESS_TABLE_NAME)
    keys = duthost.shell(keys_cmd)['stdout_lines']
    attr_cmd = 'sudo sonic-db-cli {} HGETALL "{}"'
    for key in keys:
        attrs = json.loads(duthost.shell(attr_cmd.format(CONFIG_DB_NAME, key))['stdout'])
        prefix = key.split("|")[1]
        bbr_required = attrs.get(BBR_REQUIRED_KEY, COMMON_FALSE_STRING) == COMMON_TRUE_STRING
        as_set = attrs.get(AS_SET_KEY, COMMON_FALSE_STRING) == COMMON_TRUE_STRING
        summary_only = attrs.get(SUMMARY_ONLY_KEY, COMMON_FALSE_STRING) == COMMON_TRUE_STRING
        aggregate_address_prefix_list = attrs.get(AGGREGATE_ADDRESS_PREFIX_LIST_KEY, None)
        contributing_address_prefix_list = attrs.get(CONTRIBUTING_ADDRESS_PREFIX_LIST_KEY, None)
        address = AggregateAddress(prefix, bbr_required, as_set, summary_only,
                                   aggregate_address_prefix_list, contributing_address_prefix_list)
        addresses.append(address)
    return addresses


def get_address_from_state_db(duthost):
    addresses = []
    keys_cmd = "sudo sonic-db-cli {} KEYS {}*".format(STATE_DB_NAME, BGP_AGGREGATE_ADDRESS_TABLE_NAME)
    keys = duthost.shell(keys_cmd)['stdout_lines']
    attr_cmd = 'sudo sonic-db-cli {} HGETALL "{}"'
    for key in keys:
        attrs = json.loads(duthost.shell(attr_cmd.format(STATE_DB_NAME, key))['stdout'])
        prefix = key.split("|")[1]
        state = attrs.get(ADDRESS_STATE_KEY, COMMON_EMPTY_STRING)
        bbr_required = attrs.get(BBR_REQUIRED_KEY, COMMON_FALSE_STRING) == COMMON_TRUE_STRING
        as_set = attrs.get(AS_SET_KEY, COMMON_FALSE_STRING) == COMMON_TRUE_STRING
        summary_only = attrs.get(SUMMARY_ONLY_KEY, COMMON_FALSE_STRING) == COMMON_TRUE_STRING
        aggregate_address_prefix_list = attrs.get(AGGREGATE_ADDRESS_PREFIX_LIST_KEY, None)
        contributing_address_prefix_list = attrs.get(CONTRIBUTING_ADDRESS_PREFIX_LIST_KEY, None)
        address = AggregateAddress(prefix, bbr_required, as_set, summary_only,
                                   aggregate_address_prefix_list, contributing_address_prefix_list, state)
        addresses.append(address)
    return addresses


def get_address_from_running_config(duthost):
    '''
    ip prefix-list AGG_CONTRIBUTING_ROUTES_V4 seq 5 permit 192.168.0.0/24 le 32
    ip prefix-list AGG_ROUTES_V4 seq 5 permit 192.168.0.0/24
    ip prefix-list LOCAL_VLAN_IPV4_PREFIX seq 5 permit 192.168.0.0/24
    ip prefix-list PL_LoopbackV4 seq 5 permit 10.1.0.32/32
    !
    ipv6 prefix-list LOCAL_VLAN_IPV6_PREFIX seq 10 permit fc02:1000::/64
    ipv6 prefix-list PL_LoopbackV6 seq 5 permit fc00:1::/64

    aggregate-address 192.168.0.0/24

    aggregate-address fc00::/63 as-set summary-only
    '''
    addresses = []
    agg_cmd = 'show runningconfiguration bgp | grep "aggregate-address"'
    output = duthost.shell(agg_cmd)['stdout_lines']
    pl_cmd = 'show runningconfiguration bgp | grep "prefix-list.*{}"'
    for line in output:
        parts = line.split()
        prefix = parts[1]
        as_set = AS_SET_KEY in parts
        summary_only = SUMMARY_ONLY_KEY in parts
        aggregate_address_prefix_list = None
        contributing_address_prefix_list = None
        pls = duthost.shell(pl_cmd.format(prefix))['stdout_lines']
        for pl in pls:
            if "le" in pl and contributing_address_prefix_list is None:
                contributing_address_prefix_list = pl.split()[2]
            elif aggregate_address_prefix_list is None:
                aggregate_address_prefix_list = pl.split()[2]
            else:
                pytest.fail("Too many prefix-list matched for aggregate address {}".format(prefix))
        address = AggregateAddress(prefix, None, as_set, summary_only,
                                   aggregate_address_prefix_list, contributing_address_prefix_list, state=ADDRESS_ACTIVE_STATE)
        addresses.append(address)
    return addresses


def validate_address(addresses_in_config, addresses_state, addresses_running, bbr_state):  
    failure_msgs = []
    for addr in addresses_in_config:
        expected_state = ADDRESS_ACTIVE_STATE
        if addr.bbr_required and bbr_state == BBR_DISABLED_STATE:
            expected_state = ADDRESS_INACTIVE_STATE
        addr.state = expected_state
        if addr not in addresses_state:
            for a in addresses_state:
                if a.prefix == addr.prefix:
                    failure_msgs.append("Address in config DB not identical with state DB: \nConfig DB: {}\nState DB: {}".format(addr, a))
                    break
            else:
                failure_msgs.append("Address in config DB not found in state DB: {}".format(addr.prefix))
        if addr not in addresses_running:
            for a in addresses_running:
                if a.prefix == addr.prefix:
                    failure_msgs.append("Address in config DB not identical with running config: \nConfig DB: {}\nRunning config: {}".format(addr, a))
                    break
            else:
                failure_msgs.append("Address in config DB not found in running config: {}".format(addr.prefix))
    if failure_msgs:
        pytest.fail("\n".join(failure_msgs))


def test_add_aggregate(duthost):
    address = AggregateAddress(prefix="192.168.111.0/24", bbr_required=False, as_set=True, summary_only=True,
                               aggregate_address_prefix_list="AGG_ROUTES_V4",
                               contributing_address_prefix_list="AGG_CONTRIBUTING_ROUTES_V4")
    add_aggregate(duthost, address)
    check_aggregate(duthost)
