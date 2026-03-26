/**
 * IResourceRelationRepository — ReBAC relationship storage.
 *
 * Stores (subject, relation, object) tuples, e.g.:
 *   user:alice  owns    post:123
 *   user:alice  member  org:acme
 *
 * Supports efficient "does user X have relation R to resource Y?" lookups.
 */

export type RelationType = 'owner' | 'member' | 'editor' | 'viewer' | 'admin'

export interface ResourceRelation {
  id: string
  subjectType: 'user'
  subjectId: string
  relation: RelationType
  objectType: string
  objectId: string
  createdAt: Date
  createdBy: string | null
}

export interface IResourceRelationRepository {
  hasRelation(
    subjectId: string,
    relation: RelationType,
    objectType: string,
    objectId: string,
  ): Promise<boolean>
  findRelationsForSubject(
    subjectId: string,
    objectType?: string,
  ): Promise<ResourceRelation[]>
  addRelation(
    relation: Omit<ResourceRelation, 'id' | 'createdAt'>,
  ): Promise<void>
  removeRelation(
    subjectId: string,
    relation: RelationType,
    objectType: string,
    objectId: string,
  ): Promise<void>
}
