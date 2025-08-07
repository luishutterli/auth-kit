use AuthKit;

-- ORGANIZATIONS
-- Create an Organization
insert into TOrganizations (orgName, orgStatus) values ('Test Organisation 1', 'active');
select * from TOrganizations;

-- ACCOUNTS
-- Create an Account
insert into TAccounts (accEmail, accName, accSurname, accStatus) values ('test1@example.com', 'Test1', 'Nutzer', 'active');
insert into TAccounts (accEmail, accName, accSurname, accPasswordHash, accStatus) values ('test1@example.com', 'Test1', 'Nutzer', 'PASSWORD_HASH', 'active');
select * from TAccounts;

-- Link Account to Organization
insert into TOrgMemberships (orgId, accId, orgMembStatus) values (1,1,'active');
select * from TOrgMemberships;

-- LOGIN
-- Create a Login-Attempt
insert into TLoginAttempts (accId, loginAttemptSourceIP, loginAttemptUserAgent, loginAttemptSuccess) values (1, '000.000.000', 'USER_AGENT', true);
select * from TLoginAttempts;