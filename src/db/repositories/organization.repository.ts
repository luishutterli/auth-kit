import { getDB } from "../connector";
import type { Organization, OrgMembership } from "@luishutterli/auth-kit-types";

export class OrganizationRepository {
  async createOrganization(orgName: string): Promise<Organization> {
    const db = getDB();
    const result = await db.query(
      `INSERT INTO TOrganizations 
       (orgName, orgStatus)
       VALUES ($1, $2)
       RETURNING *`,
      [orgName, "active"],
    );

    return result.rows[0];
  }

  async getOrganizationById(orgId: number): Promise<Organization | null> {
    const db = getDB();
    const result = await db.query(
      "SELECT * FROM TOrganizations WHERE orgId = $1 AND orgStatus != $2",
      [orgId, "deleted"],
    );

    return result.rows[0] ?? null;
  }

  async addUserToOrganization(orgId: number, accId: number): Promise<OrgMembership> {
    const db = getDB();
    const result = await db.query(
      `INSERT INTO TOrgMemberships 
       (orgId, accId, orgMembStatus)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [orgId, accId, "active"],
    );

    return result.rows[0];
  }

  async getUserOrganizations(accId: number): Promise<Organization[]> {
    const db = getDB();
    const result = await db.query(
      `SELECT o.* FROM TOrganizations o
       JOIN TOrgMemberships m ON o.orgId = m.orgId
       WHERE m.accId = $1 
       AND m.orgMembStatus = 'active'
       AND o.orgStatus = 'active'`,
      [accId],
    );

    return result.rows;
  }

  async isUserMemberOfOrganization(orgId: number, accId: number): Promise<boolean> {
    const db = getDB();
    const result = await db.query(
      `SELECT * FROM TOrgMemberships
       WHERE orgId = $1 AND accId = $2 AND orgMembStatus = 'active'`,
      [orgId, accId],
    );

    return result.rowCount ? result.rowCount > 0 : false;
  }

  async updateOrganization(
    orgId: number,
    updates: Partial<Organization>,
  ): Promise<Organization | null> {
    const db = getDB();

    const updateFields: string[] = [];
    const values: (string | number | boolean)[] = [];
    let paramIndex = 1;

    const disallowedFields = ["orgId", "orgCreated"];

    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined || disallowedFields.includes(key)) {
        continue;
      }
      updateFields.push(`${key} = $${paramIndex}`);
      values.push(value instanceof Date ? value.toISOString() : value);
      paramIndex++;
    }

    if (updateFields.length === 0) {
      return this.getOrganizationById(orgId);
    }

    values.push(orgId);

    const result = await db.query(
      `UPDATE TOrganizations SET ${updateFields.join(", ")} WHERE orgId = $${paramIndex} RETURNING *`,
      values,
    );

    return result.rows[0] ?? null;
  }
}
