import type { Result } from './Result'

/**
 * Use-case interface: every application use case implements this contract.
 * I = input DTO, O = output DTO, E = domain error (defaults to DomainError)
 */
export interface IUseCase<I, O, E = import('./Result').DomainError> {
  execute(input: I): Promise<Result<O, E>>
}
