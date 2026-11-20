"""权限服务：基线许可、字段提级、临时授权、撤销、过期、版本号。"""


from app.models import HitSource, Sensitivity


def test_baseline_allows_public_and_internal(perms):
    perms.set_baseline("t", "u", Sensitivity.INTERNAL)
    acc_pub = perms.evaluate_field("t", "u", "id", Sensitivity.PUBLIC)
    acc_int = perms.evaluate_field("t", "u", "name", Sensitivity.INTERNAL)
    acc_con = perms.evaluate_field("t", "u", "id_card", Sensitivity.CONFIDENTIAL)
    assert acc_pub.allowed and acc_pub.source == HitSource.BASELINE
    assert acc_int.allowed
    assert not acc_con.allowed and acc_con.source == HitSource.DENIED


def test_field_clearance_overrides_baseline(perms):
    perms.set_baseline("t", "u", Sensitivity.PUBLIC)
    perms.add_field_clearance("t", "u", "id_card", Sensitivity.SECRET)
    acc = perms.evaluate_field("t", "u", "id_card", Sensitivity.CONFIDENTIAL)
    assert acc.allowed and acc.source == HitSource.BASELINE
    # 其他字段仍按基线
    assert not perms.evaluate_field("t", "u", "salary", Sensitivity.SECRET).allowed


def test_temporary_grant_grants_and_is_recorded(perms):
    perms.set_baseline("t", "u", Sensitivity.INTERNAL)
    gid = perms.create_grant("t", "u", Sensitivity.SECRET, 3600, field_name="salary")
    acc = perms.evaluate_field("t", "u", "salary", Sensitivity.SECRET)
    assert acc.allowed and acc.source == HitSource.GRANT and acc.grant_id == gid


def test_field_specific_grant_does_not_leak_to_other_fields(perms):
    perms.set_baseline("t", "u", Sensitivity.INTERNAL)
    perms.create_grant("t", "u", Sensitivity.SECRET, 3600, field_name="salary")
    assert not perms.evaluate_field("t", "u", "id_card", Sensitivity.CONFIDENTIAL).allowed


def test_tenant_wide_grant_covers_all_fields(perms):
    perms.set_baseline("t", "u", Sensitivity.PUBLIC)
    perms.create_grant("t", "u", Sensitivity.SECRET, 3600)  # 无 field 限制
    assert perms.evaluate_field("t", "u", "x", Sensitivity.CONFIDENTIAL).allowed
    assert perms.evaluate_field("t", "u", "y", Sensitivity.SECRET).allowed


def test_grant_expires_with_virtual_clock(perms, clk):
    perms.set_baseline("t", "u", Sensitivity.INTERNAL)
    perms.create_grant("t", "u", Sensitivity.SECRET, 100, field_name="salary")
    assert perms.evaluate_field("t", "u", "salary", Sensitivity.SECRET).allowed
    clk.advance(99)
    assert perms.evaluate_field("t", "u", "salary", Sensitivity.SECRET).allowed
    clk.advance(2)  # 超过 100s TTL
    assert not perms.evaluate_field("t", "u", "salary", Sensitivity.SECRET).allowed


def test_revoke_grant_is_idempotent_and_bumps_version(perms):
    gid = perms.create_grant("t", "u", Sensitivity.SECRET, 100)
    v0 = perms.permission_version
    assert perms.revoke_grant(gid) is True
    assert perms.permission_version == v0 + 1
    # 重复撤销不产生新版本
    assert perms.revoke_grant(gid) is False
    assert perms.permission_version == v0 + 1
    assert perms.revoke_grant("grant_missing") is False


def test_permission_version_bumps_on_baseline_change(perms):
    v0 = perms.permission_version
    perms.set_baseline("t", "u", Sensitivity.PUBLIC)
    assert perms.permission_version == v0 + 1


def test_cross_tenant_isolation(perms):
    perms.set_baseline("t1", "u", Sensitivity.SECRET)
    perms.set_baseline("t2", "u", Sensitivity.PUBLIC)
    assert not perms.evaluate_field("t2", "u", "f", Sensitivity.INTERNAL).allowed
    assert perms.evaluate_field("t1", "u", "f", Sensitivity.SECRET).allowed


def test_depends_on_grants(perms, clk):
    g1 = perms.create_grant("t", "u", Sensitivity.SECRET, 100, field_name="a")
    g2 = perms.create_grant("t", "u", Sensitivity.SECRET, 100, field_name="b")
    assert perms.depends_on_grants("t", "u", [g1, g2])
    perms.revoke_grant(g1)
    assert perms.depends_on_grants("t", "u", [g1, g2])  # g2 仍有效
    perms.revoke_grant(g2)
    assert not perms.depends_on_grants("t", "u", [g1, g2])
