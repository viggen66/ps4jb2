Enhanced exploit race condition mitigation for original sleirsgoevy ps4jb2.

1) Each critical thread is bound to a specific core 
2) Real-time scheduling (threads are promoted to increased priority, to prevent thread preemption by OS background tasks)
3) Malloc sprays are performed on all available cores, for increased reclaiming freed memory during UAF and exploit success.
4) The userland ROP chain is only executed after trigger_uaf(), fake_pktopts(), and IDT corruption has succeed 
5) Safety exit to ensure OS stability
