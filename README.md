Enhanced exploit race condition mitigation for original Sleirsgoevy's PS4jb2.

1) Each critical thread is bound to a specific core 
2) Malloc sprays are performed on all available cores, for increased reclaiming freed memory during UAF and exploit success.
3) The userland ROP chain is only executed after trigger_uaf(), fake_pktopts(), and IDT corruption has succeed
4) Memory structures cleanup after successful exploit
5) Safety exit to ensure OS stability


https://viggen66.github.io/Webhost/
