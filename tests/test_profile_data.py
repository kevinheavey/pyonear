from pyonear.transaction import ProfileData
from pyonear.config import ActionCosts, ExtCosts

MAX_U64 = 18_446_744_073_709_551_615

def test_no_panic_on_overflow() -> None:
    profile_data = ProfileData()
    profile_data.add_action_cost(ActionCosts.function_call, MAX_U64)
    profile_data.add_action_cost(ActionCosts.function_call, MAX_U64)

    res = profile_data.get_action_cost(ActionCosts.function_call)
    assert res == MAX_U64


def test_merge() -> None:
    profile_data = ProfileData()
    profile_data.add_action_cost(ActionCosts.function_call, 111)
    profile_data.add_ext_cost(ExtCosts.storage_read_base, 11)

    profile_data2 = ProfileData()
    profile_data2.add_action_cost(ActionCosts.function_call, 222)
    profile_data2.add_ext_cost(ExtCosts.storage_read_base, 22)

    profile_data.merge(profile_data2)
    assert profile_data.get_action_cost(ActionCosts.function_call) == 333
    assert profile_data.get_ext_cost(ExtCosts.storage_read_base) == 33
