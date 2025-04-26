import { OrganizationRepository } from "../db/repositories/organization.repository";
import type { Organization } from "@luishutterli/auth-kit-types";
import { DatabaseError, NotFoundError } from "@luishutterli/auth-kit-types";

export class OrganizationService {
  private readonly orgRepo: OrganizationRepository;

  constructor() {
    this.orgRepo = new OrganizationRepository();
  }

  async createOrganization(orgName: string, userId: number): Promise<Organization> {
    try {
      const organization = await this.orgRepo.createOrganization(orgName);

      await this.orgRepo.addUserToOrganization(organization.orgId, userId);

      return organization;
    } catch (error) {
      throw new DatabaseError("Failed to create organization", error as Error);
    }
  }

  async getOrganization(orgId: number): Promise<Organization> {
    try {
      const organization = await this.orgRepo.getOrganizationById(orgId);
      if (!organization) {
        throw new NotFoundError("Organization", orgId);
      }
      return organization;
    } catch (error) {
      if (error instanceof NotFoundError) {
        throw error;
      }
      throw new DatabaseError("Failed to get organization", error as Error);
    }
  }

  async getUserOrganizations(userId: number): Promise<Organization[]> {
    try {
      return await this.orgRepo.getUserOrganizations(userId);
    } catch (error) {
      throw new DatabaseError("Failed to get user organizations", error as Error);
    }
  }

  async isUserMemberOfOrganization(orgId: number, userId: number): Promise<boolean> {
    try {
      return await this.orgRepo.isUserMemberOfOrganization(orgId, userId);
    } catch (error) {
      throw new DatabaseError("Failed to check organization membership", error as Error);
    }
  }

  async addUserToOrganization(orgId: number, userId: number): Promise<boolean> {
    try {
      const organization = await this.orgRepo.getOrganizationById(orgId);
      if (!organization) {
        throw new NotFoundError("Organization", orgId);
      }

      await this.orgRepo.addUserToOrganization(orgId, userId);
      return true;
    } catch (error) {
      if (error instanceof NotFoundError) {
        throw error;
      }
      throw new DatabaseError("Failed to add user to organization", error as Error);
    }
  }

  async updateOrganization(
    orgId: number,
    updates: Partial<Organization>,
  ): Promise<Organization> {
    try {
      const updatedOrg = await this.orgRepo.updateOrganization(orgId, updates);
      if (!updatedOrg) {
        throw new NotFoundError("Organization", orgId);
      }
      return updatedOrg;
    } catch (error) {
      if (error instanceof NotFoundError) {
        throw error;
      }
      throw new DatabaseError("Failed to update organization", error as Error);
    }
  }
}
