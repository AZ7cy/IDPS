import pytest

from netsentinel.settings import Settings
from netsentinel.wifi import (PLAN_MARGIN_PX, plan_fraction_to_metres, plan_scale, plan_size_px, resize_plan,
                              room_from_drag, validate_plan)

PLAN = {'width': 12.0, 'length': 9.0, 'rooms': [{'name': 'Kitchen', 'x': 0.0, 'y': 0.0, 'w': 4.0, 'h': 3.0}]}


def test_validate_plan():
    assert validate_plan({}) and validate_plan(PLAN)
    assert not validate_plan({'width': 1.0, 'length': 9.0})                 # too small
    assert not validate_plan({'width': 12.0, 'length': True})               # bool is not a number
    assert not validate_plan({'width': 12.0, 'length': 9.0, 'rooms': [{'name': 'Out', 'x': 10.0, 'y': 0.0,
                                                                        'w': 4.0, 'h': 2.0}]})   # past the wall
    assert not validate_plan({'width': 12.0, 'length': 9.0, 'rooms': [{'name': 'Bad', 'x': 0, 'y': 0,
                                                                        'w': 0, 'h': 2}]})


def test_fraction_to_metres_round_trip():
    w_px, h_px = plan_size_px(PLAN)
    s = plan_scale(PLAN)
    fx, fy = (PLAN_MARGIN_PX + 3 * s) / w_px, (PLAN_MARGIN_PX + 2 * s) / h_px
    assert plan_fraction_to_metres(PLAN, fx, fy) == pytest.approx((3.0, 2.0))
    assert plan_fraction_to_metres(PLAN, 0.0, 1.0) == (0.0, 9.0)            # margins clamp to the walls


def test_room_from_drag_snaps_and_orders():
    w_px, h_px = plan_size_px(PLAN)
    s = plan_scale(PLAN)
    frac = lambda mx, my: ((PLAN_MARGIN_PX + mx * s) / w_px, (PLAN_MARGIN_PX + my * s) / h_px)
    room = room_from_drag(PLAN, frac(8.1, 6.9), frac(5.2, 4.1), ' Lounge ')   # dragged bottom-right to top-left
    assert room == {'name': 'Lounge', 'x': 5.0, 'y': 4.0, 'w': 3.0, 'h': 3.0}
    assert room_from_drag(PLAN, frac(1.0, 1.0), frac(1.1, 1.1), 'tiny') is None
    assert validate_plan(dict(PLAN, rooms=PLAN['rooms'] + [room]))


def test_resize_keeps_rooms_that_fit():
    assert resize_plan(PLAN, 5.0, 5.0)['rooms'] == PLAN['rooms']
    assert resize_plan(PLAN, 3.0, 5.0)['rooms'] == []


def test_plan_setting_round_trip(tmp_path):
    path = tmp_path / 'settings.json'
    s = Settings(path)
    assert s.set('wifi_plan', PLAN) and not s.set('wifi_plan', {'width': 'x'})
    assert Settings(path).get('wifi_plan') == PLAN


def test_snap_opening_to_nearest_wall():
    from netsentinel.wifi import snap_opening
    door = snap_opening(PLAN, 2.0, 3.2, 0.9)        # 0.2 m below the kitchen's bottom wall (y = 3)
    assert door == {'x': 2.0, 'y': 3.0, 'vertical': False, 'w': 0.9}
    edge = snap_opening(PLAN, 11.9, 0.2, 1.2)       # in the corner: slides along the wall to fit
    assert edge is not None and edge['w'] == 1.2
    assert edge['vertical'] or 0.6 <= edge['x'] <= 11.4
    assert snap_opening(PLAN, 8.0, 6.0, 0.9) is None    # middle of open floor, no wall nearby
    assert validate_plan(dict(PLAN, doors=[door], windows=[edge], routers=[{'name': 'AP', 'x': 6.0, 'y': 4.5}]))
    assert not validate_plan(dict(PLAN, routers=[{'name': 'AP', 'x': 60.0, 'y': 1.0}]))


def test_resize_drops_openings_off_walls():
    from netsentinel.wifi import snap_opening
    door = snap_opening(PLAN, 2.0, 3.0, 0.9)
    window = snap_opening(PLAN, 12.0, 6.0, 1.2)     # on the outer right wall
    plan = dict(PLAN, doors=[door], windows=[window])
    smaller = resize_plan(plan, 10.0, 9.0)          # the right wall moves, so the window goes
    assert smaller['doors'] == [door] and 'windows' not in smaller
