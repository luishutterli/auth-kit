/* -----------------------------------------------------
    auth_kit-init-default-groups.sql

    Setup Script for the AuthKit database to initialize default groups.

    Author:  Luis Hutterli
    Date:    04.08.2025

    History:
    Version     Date        Who      Description
    1.0         04.08.2025  Luis     created
    
    Copyright © 2025 Luis Hutterli, Switzerland. All rights reserved.
    This program/script is intended for the auth kit service built for swisscounts.ch
----------------------------------------------------- */

use AuthKit;
start transaction;

-- Create the universal permission
insert into TPermissions (permId, permName, permDescription) values ('*', 'Universal', 'Default permission for all actions');

-- Create the default owner group
insert into TGroups (groupName, orgId) value ('Owner', null); -- orgId is null for a globally defined group
set @ownerGroupId = last_insert_id();

-- Grant the universal permission to the owner group
insert into TGroupGrants (groupId, permId, groupGrantStatus) value (@ownerGroupId, '*', 'active');


-- Commit the transaction
commit;