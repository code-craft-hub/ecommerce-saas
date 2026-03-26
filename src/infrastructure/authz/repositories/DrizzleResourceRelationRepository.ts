/**
 * DrizzleResourceRelationRepository — PostgreSQL implementation of IResourceRelationRepository.
 */

import { and, eq } from 'drizzle-orm'
import { v4 as uuidv4 } from 'uuid'
import type { DB } from '../../persistence/db'
import { resourceRelations as relTable } from '../../persistence/schema'
import type {
  IResourceRelationRepository,
  RelationType,
  ResourceRelation,
} from '../../../domain/authz/repositories/IResourceRelationRepository'

export class DrizzleResourceRelationRepository
  implements IResourceRelationRepository
{
  constructor(private readonly db: DB) {}

  async hasRelation(
    subjectId: string,
    relation: RelationType,
    objectType: string,
    objectId: string,
  ): Promise<boolean> {
    const [row] = await this.db
      .select({ id: relTable.id })
      .from(relTable)
      .where(
        and(
          eq(relTable.subjectId, subjectId),
          eq(relTable.relation, relation),
          eq(relTable.objectType, objectType),
          eq(relTable.objectId, objectId),
        ),
      )
      .limit(1)

    return !!row
  }

  async findRelationsForSubject(
    subjectId: string,
    objectType?: string,
  ): Promise<ResourceRelation[]> {
    const conditions = objectType
      ? and(eq(relTable.subjectId, subjectId), eq(relTable.objectType, objectType))
      : eq(relTable.subjectId, subjectId)

    const rows = await this.db
      .select()
      .from(relTable)
      .where(conditions)

    return rows.map((r) => ({
      id: r.id,
      subjectType: r.subjectType as 'user',
      subjectId: r.subjectId,
      relation: r.relation as RelationType,
      objectType: r.objectType,
      objectId: r.objectId,
      createdAt: r.createdAt,
      createdBy: r.createdBy,
    }))
  }

  async addRelation(
    relation: Omit<ResourceRelation, 'id' | 'createdAt'>,
  ): Promise<void> {
    await this.db
      .insert(relTable)
      .values({
        id: uuidv4(),
        subjectType: relation.subjectType,
        subjectId: relation.subjectId,
        relation: relation.relation,
        objectType: relation.objectType,
        objectId: relation.objectId,
        createdBy: relation.createdBy,
      })
      .onConflictDoNothing()
  }

  async removeRelation(
    subjectId: string,
    relation: RelationType,
    objectType: string,
    objectId: string,
  ): Promise<void> {
    await this.db
      .delete(relTable)
      .where(
        and(
          eq(relTable.subjectId, subjectId),
          eq(relTable.relation, relation),
          eq(relTable.objectType, objectType),
          eq(relTable.objectId, objectId),
        ),
      )
  }
}
