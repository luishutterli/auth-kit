import { zValidator } from "@hono/zod-validator";
import { DatabaseError, type User } from "@luishutterli/auth-kit-types";
import { Hono } from "hono";
import type { ResultSetHeader, RowDataPacket } from "mysql2";
import z from "zod";
import { getConfig } from "../config/config";
import { getConnection } from "../db/connection";
import { dummyHashVerify, generateDBHash, verifyPassword } from "../util/hash";
import { validatePasswordWithError } from "../util/password";
import { clearTokenPair, setTokenPair, validateRefreshTokenCookie } from "./cookies";
import { createRefreshToken, createSignedJWT, jwtMiddleware } from "./jwt";

const config = getConfig();

const app = new Hono();

// /signup
const signupUserSchema = z.object({
  email: z.email().max(255),
  name: z.string().min(2).max(45),
  surname: z.string().min(2).max(45),
  password: z.string().min(2),
});

app.post("/signup", zValidator("json", signupUserSchema), async (c) => {
  const { email, name, surname, password } = c.req.valid("json");
  const passwordError = validatePasswordWithError(password);
  if (passwordError) {
    return c.json({ error: passwordError }, 400);
  }

  const connection = await getConnection();
  try {
    await connection.beginTransaction();

    // Step 1: Check if user already exists
    const [existingUsers] = await connection.execute<RowDataPacket[]>(
      "select * from TAccounts where accEmail = ?",
      [email],
    );
    if (existingUsers.length > 0) {
      return c.json({ error: "Email already in use" }, 400);
    }

    // Step 2: Hash and salt the password
    const hashedPassword = generateDBHash(password);

    // Step 3: Insert the user into db (and get id)
    const [result] = await connection.execute<ResultSetHeader>(
      "insert into TAccounts (accEmail, accName, accSurname, accPasswordHash, accStatus) values (?, ?, ?, ?, 'active')",
      [email, name, surname, hashedPassword],
    );
    const userId = result.insertId;

    await connection.commit();

    // Step 4: Login the user
    const user: User = {
      id: userId,
      email,
      name,
      surname,
      emailVerified: false,
      createdAt: new Date(),
      twoFactorEnabled: false,
    };
    const accessToken = createSignedJWT(user);
    const refreshToken = createRefreshToken(user.id);
    setTokenPair(c, accessToken, refreshToken);

    console.log("New user created with id:", userId);
    return c.json({ success: true, userId }, 201);
  } catch (error) {
    await connection.rollback();
    if (error instanceof DatabaseError) {
      throw error;
    }
    throw new DatabaseError("Failed to sign up user", error as Error);
  } finally {
    connection.release();
  }
});

// /login
const loginUserSchema = z.object({
  email: z.email(),
  password: z.string().min(2),
});

const wrongCredentialMessage = "Wrong email or password";

app.post("/login", zValidator("json", loginUserSchema), async (c) => {
  const { email, password } = c.req.valid("json");

  const connection = await getConnection();
  try {
    // Step 1: Check if user exists and get all user data
    const [users] = await connection.execute<
      RowDataPacket[] &
        {
          accId: number;
          accEmail: string;
          accName: string;
          accSurname: string;
          accPasswordHash: string;
          accEmailVerified: number;
          accCreated: Date;
        }[]
    >(
      "select accId, accEmail, accName, accSurname, accPasswordHash, accEmailVerified, accCreated from TAccounts where accEmail = ? and accStatus = 'active'",
      [email],
    );

    if (users.length === 0) {
      // NOTE: To mitigate email enumeration via timing attacks, a dummy hash is calculated
      if (config.emailEnumerationProtection) dummyHashVerify();
      return c.json({ success: false, error: wrongCredentialMessage }, 401);
    }
    const userRow = users[0];

    const passwordValid = verifyPassword(userRow.accPasswordHash, password);
    if (!passwordValid) {
      return c.json({ success: false, error: wrongCredentialMessage }, 401);
    }

    // Step 2: Create User object for JWT
    const user: User = {
      id: userRow.accId,
      email: userRow.accEmail,
      name: userRow.accName,
      surname: userRow.accSurname,
      emailVerified: userRow.accEmailVerified === 1,
      createdAt: userRow.accCreated,
      twoFactorEnabled: false,
    };

    // Step 3: Create JWT and return
    const accessToken = createSignedJWT(user);
    const refreshToken = createRefreshToken(user.id);
    setTokenPair(c, accessToken, refreshToken);

    return c.json(
      {
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          surname: user.surname,
          emailVerified: user.emailVerified,
          twoFactorEnabled: user.twoFactorEnabled,
        },
      },
      200,
    );
  } catch (error) {
    if (error instanceof DatabaseError) {
      throw error;
    }
    throw new DatabaseError("Failed to log in user", error as Error);
  } finally {
    connection.release();
  }
});

// /refresh
app.post("/refresh", async (c) => {
  const refreshValidation = validateRefreshTokenCookie(c);

  if (!refreshValidation.valid) {
    return c.json({ success: false, error: "Invalid or missing refresh token" }, 401);
  }

  const connection = await getConnection();
  try {
    const [users] = await connection.execute<
      RowDataPacket[] &
        {
          accId: number;
          accEmail: string;
          accName: string;
          accSurname: string;
          accEmailVerified: number;
          accCreated: Date;
        }[]
    >(
      "select accId, accEmail, accName, accSurname, accEmailVerified, accCreated from TAccounts where accId = ? and accStatus = 'active'",
      [refreshValidation.userId],
    );

    if (users.length === 0) {
      return c.json({ success: false, error: "User not found or inactive" }, 404);
    }

    const userRow = users[0];
    const user: User = {
      id: userRow.accId,
      email: userRow.accEmail,
      name: userRow.accName,
      surname: userRow.accSurname,
      emailVerified: userRow.accEmailVerified === 1,
      createdAt: userRow.accCreated,
      twoFactorEnabled: false,
    };

    const newAccessToken = createSignedJWT(user);
    const newRefreshToken = createRefreshToken(user.id);
    setTokenPair(c, newAccessToken, newRefreshToken);

    return c.json(
      {
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          surname: user.surname,
          emailVerified: user.emailVerified,
          twoFactorEnabled: user.twoFactorEnabled,
        },
      },
      200,
    );
  } catch (error) {
    if (error instanceof DatabaseError) {
      throw error;
    }
    throw new DatabaseError("Failed to refresh token", error as Error);
  } finally {
    connection.release();
  }
});

// /logout
app.post("/logout", async (c) => {
  clearTokenPair(c);
  return c.json({ success: true }, 200);
});

// /me
app.get("/me", jwtMiddleware, async (c) => {
  const userId = c.get("userId");

  const connection = await getConnection();
  try {
    // Step 1: Get fresh user data from database
    const [users] = await connection.execute<
      RowDataPacket[] &
        {
          accId: number;
          accEmail: string;
          accName: string;
          accSurname: string;
          accEmailVerified: number;
          accCreated: Date;
          accStatus: string;
        }[]
    >(
      "select accId, accEmail, accName, accSurname, accEmailVerified, accCreated, accStatus from TAccounts where accId = ? and accStatus = 'active'",
      [userId],
    );

    if (users.length === 0)
      return c.json({ success: false, error: "User not found or inactive" }, 404);

    const userRow = users[0];

    // Step 2: Create User object
    const user: User = {
      id: userRow.accId,
      email: userRow.accEmail,
      name: userRow.accName,
      surname: userRow.accSurname,
      emailVerified: userRow.accEmailVerified === 1,
      createdAt: userRow.accCreated,
      twoFactorEnabled: false,
    };

    return c.json(
      {
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          surname: user.surname,
          emailVerified: user.emailVerified,
          createdAt: user.createdAt,
          twoFactorEnabled: user.twoFactorEnabled,
        },
      },
      200,
    );
  } catch (error) {
    if (error instanceof DatabaseError) {
      throw error;
    }
    throw new DatabaseError("Failed to get user information", error as Error);
  } finally {
    connection.release();
  }
});

// /org/create
const createOrgSchema = z.object({
  name: z.string().min(3).max(255),
});
app.post("/org/create", jwtMiddleware, zValidator("json", createOrgSchema), async (c) => {
  const { name } = c.req.valid("json");

  const connection = await getConnection();
  try {
    await connection.beginTransaction();

    // Step 2: Create organization
    const [orgResult] = await connection.execute<ResultSetHeader>(
      "insert into TOrganizations (orgName, orgStatus) values (?, 'active')",
      [name],
    );
    const orgId = orgResult.insertId;

    // Step 3: Add current user to organization
    const [_orgMembResult] = await connection.execute<ResultSetHeader>(
      "insert into TOrgMemberships (orgId, accId, orgMembStatus) values (?, ?, 'active')",
      [orgId, c.get("userId")],
    );

    // Step 4: Add owner role to the user
    const [groupMembResult] = await connection.execute<ResultSetHeader>(
      "insert into TGroupMemberships (groupId, accId, orgId, groupMembStatus) select groupId, ?, ?, 'active' from TGroups where groupName = 'Owner' and orgId is null limit 1",
      [c.get("userId"), orgId],
    );

    if (groupMembResult.affectedRows !== 1)
      throw new DatabaseError("Failed to assign owner role to the user");

    await connection.commit();

    console.log("New organization created with id:", orgId);
    return c.json({ success: true, orgId }, 201);
  } catch (error) {
    await connection.rollback();
    if (error instanceof DatabaseError) {
      throw error;
    }
    throw new DatabaseError("Failed to create organization", error as Error);
  } finally {
    connection.release();
  }
});

export { app as authApp };
