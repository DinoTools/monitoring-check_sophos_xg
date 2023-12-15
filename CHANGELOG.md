Changelog
=========

0.4.2 (2023-12-15)
------------------

- Update checks
  - ha - Add option to report all WARNING states as CRITICAL

0.4.1 (2023-10-18)
------------------

- Remove checks
  - vpn - We get wrong or unexpected values from the device.
- Fix checks
  - ha - Fix issue not detecting some HA failures

0.4 (2023-05-26)
----------------

- Add new checks
  - ha - Check HA state of the device
- Add additional documentation and render and publish it as GH pages
- Add warning about the VPN plugin

0.3 (2022-11-17)
----------------

- Add new checks
  - service - To check the state of the services
  - vpn - To check Site-to-Site VPN connections

0.2 (2022-10-10)
----------------

- Add new checks
  - disk - To check the disk
  - memory - To check the memory and swap usage
- Fix typo in license check
- Fix date parsing in license check

0.1 (2022-09-03)
----------------

- Initial version
