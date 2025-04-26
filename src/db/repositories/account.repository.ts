import { getDB } from "../connector";
import type { Account, User } from "@luishutterli/auth-kit-types";

export class AccountRepository {
  async createAccount(
    account: Omit<Account, "accId" | "accCreated" | "accJWTversion">,
  ): Promise<Account> {
    const db = getDB();
    const result = await db.query(
      `INSERT INTO TAccounts 
       (accEmail, accName, accSurname, accPasswordHash, accEmailVerified, accStatus)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        account.accEmail,
        account.accName,
        account.accSurname,
        account.accPasswordHash,
        account.accEmailVerified,
        account.accStatus,
      ],
    );

    return result.rows[0];
  }

  async getAccountById(id: number): Promise<Account | null> {
    const db = getDB();
    const result = await db.query(
      "SELECT * FROM TAccounts WHERE accId = $1 AND accStatus != $2",
      [id, "deleted"],
    );

    return result.rows[0] || null;
  }

  async getAccountByEmail(email: string): Promise<Account | null> {
    const db = getDB();
    const result = await db.query(
      "SELECT * FROM TAccounts WHERE accEmail = $1 AND accStatus != $2",
      [email, "deleted"],
    );

    return result.rows[0] || null;
  }

  async updateAccount(id: number, updates: Partial<Account>): Promise<Account | null> {
    const db = getDB();

    const updateFields: string[] = [];
    const values: (string | number | boolean)[] = [];
    let paramIndex = 1;

    const disallowedFields = ["accId", "accCreated", "accJWTversion"];

    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined || disallowedFields.includes(key)) {
        continue;
      }
      updateFields.push(`${key} = $${paramIndex}`);
      values.push(value instanceof Date ? value.toISOString() : value);
      paramIndex++;
    }

    if (updateFields.length === 0) {
      return this.getAccountById(id);
    }

    values.push(id);

    const result = await db.query(
      `UPDATE TAccounts SET ${updateFields.join(", ")} WHERE accId = $${paramIndex} RETURNING *`,
      values,
    );

    return result.rows[0] ?? null;
  }

  async incrementJWTVersion(id: number): Promise<boolean> {
    const db = getDB();
    const result = await db.query(
      "UPDATE TAccounts SET accJWTversion = accJWTversion + 1 WHERE accId = $1 RETURNING accJWTversion",
      [id],
    );

    return result.rowCount ? result.rowCount > 0 : false;
  }

  mapAccountToUser(account: Account): User {
    return {
      id: account.accId,
      email: account.accEmail,
      name: account.accName,
      surname: account.accSurname,
      emailVerified: account.accEmailVerified,
      createdAt: account.accCreated,
      twoFactorEnabled: false, // Placeholder
      // TODO: Add users organizations and permissions
    };
  }

  async recordLoginAttempt(
    accId: number,
    ip: string,
    userAgent: string,
    success: boolean,
  ): Promise<void> {
    const db = getDB();
    await db.query(
      `INSERT INTO TLoginAttempts 
       (loginAttemptSourceIP, loginAttemptUserAgent, loginAttemptSuccess, accId)
       VALUES ($1, $2, $3, $4)`,
      [ip, userAgent, success, accId],
    );
  }
}
