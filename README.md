用户申请删除数据后，销毁了主密钥，但历史备份里用旧密钥加的数据还能解开：一是销毁只把当前节点标记为已销毁而不递归传播到全部后代；二是可达性判定只看节点自身的标记而祖先销毁后仍把后代判为可用；三是子密钥派生只用索引不用父密钥导致不同父节点下的兄弟密钥相同；四是子密钥派生允许重复索引导致两个子节点共用同一密钥；五是解密检查只尝试用密钥解密而不复核销毁状态导致标记后仍能解出明文；六是缓存不按销毁状态清理导致旧的密钥材料仍可被使用；七是缓存清理只删除键值而不删除派生来源导致重新派生仍得到同一密钥；八是残留检测只检查主副本而忽略备份副本；九是残留检测按文件名匹配而不按内容验证导致内容残留漏检；十是批量销毁复用树状态导致第二个请求命中第一个请求的销毁标记。shred/_impl.py 是核心，tests/test_shred.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

    python -m pytest tests -q

交付状态必须恰好是 15 failed，且每条失败都来自 _impl.py 中的 NotImplementedError。修完之后目标是 15 passed。

## 字段

| 字段 | 值 |
| --- | --- |
| 赛道 | 安全 |
| 方向 | 漏洞检测与攻防 |
| 类型 | Bugfix |
| 环境 | Python 3, pytest |
| 依赖 | 无外部依赖 |

## 约束

- tests/test_shred.py 是评测契约，不可修改。
- 只允许实现 shred/_impl.py 中的 8 个桩，不要改签名。
- 唯一实现文件是 shred/_impl.py；shred/api.py 和 shred/__init__.py 只负责再导出。
- 不使用网络、外部服务或第三方依赖。

## 门面布局

    sec-crypto-shredding/
      README.md
      conftest.py
      shred/
        __init__.py      # 从 shred.api 导出
        _impl.py         # 唯一实现文件，恰好 8 个桩，全部 raise NotImplementedError
        api.py           # 只做再导出
      tests/
        test_shred.py

## 8 个桩

1. build_tree(root, children) -> dict：构建密钥层级，环必须报错。
2. derive_child(parent_key, index) -> bytes：子密钥派生，索引参与且不可重复。
3. destroy(tree, node_id, now) -> dict：销毁节点，必须递归传播到全部后代。
4. is_destroyed(tree, node_id) -> bool：可达性判定，祖先被销毁时后代视为已销毁。
5. decrypt_check(tree, node_id, ciphertext) -> bool：解密尝试，节点已销毁必须失败。
6. purge_cache(cache, tree) -> int：清除缓存中已销毁节点的密钥材料。
7. verify_no_residual(tree, backups) -> list：残留检测，返回仍可解出明文的副本。
8. shred_batch(requests, policy, now) -> dict：批量销毁，各请求独立。

## 15 个测试

1. test_destroy_propagates_to_all_descendants
2. test_is_destroyed_true_for_descendant_of_destroyed_ancestor
3. test_derive_child_depends_on_parent_key_and_index
4. test_build_tree_rejects_duplicate_sibling_index_and_cycles
5. test_decrypt_check_rechecks_destroyed_status
6. test_purge_cache_removes_keys_of_descendants_of_destroyed_ancestor
7. test_purge_cache_removes_derivation_source_not_only_key
8. test_verify_no_residual_checks_every_backup
9. test_verify_no_residual_uses_content_not_filename
10. test_shred_batch_requests_are_independent
11. test_destroyed_node_decrypt_fails
12. test_destroyed_parent_child_decrypt_fails
13. test_purged_cache_cannot_rederive_destroyed_key
14. test_backup_residual_is_detected
15. test_batch_destruction_matches_individual_destruction

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

