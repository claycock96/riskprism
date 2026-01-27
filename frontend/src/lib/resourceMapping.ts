import { ResourceChange, RiskFinding } from './types'

export interface ResourceMapping {
  [hash: string]: {
    address: string
    type: string
  }
}

/**
 * Create a mapping from resource hash to resource information
 */
export function createResourceMapping(
  diffSkeleton: ResourceChange[],
  riskFindings: RiskFinding[]
): ResourceMapping {
  const mapping: ResourceMapping = {}

  // Add from diff_skeleton
  diffSkeleton.forEach(resource => {
    if (resource.resource_address) {
      mapping[resource.resource_ref] = {
        address: resource.resource_address,
        type: resource.resource_type,
      }
    }
  })

  // Add from risk findings (in case diff_skeleton is incomplete)
  riskFindings.forEach(finding => {
    if (!mapping[finding.resource_ref] && finding.resource_type) {
      mapping[finding.resource_ref] = {
        address: finding.resource_ref, // Fallback to hash
        type: finding.resource_type,
      }
    }
  })

  return mapping
}

/**
 * Extract just the resource name from the full address
 * e.g., "aws_security_group.web_server" -> "web_server"
 */
export function extractResourceName(address: string): string {
  const parts = address.split('.')
  return parts.length > 1 ? parts.slice(1).join('.') : address
}

/**
 * Format a resource reference for display
 */
export function formatResourceRef(
  hash: string,
  mapping: ResourceMapping,
  includeType: boolean = true
): string {
  const resource = mapping[hash]

  if (!resource) {
    return hash
  }

  const name = extractResourceName(resource.address)

  if (includeType) {
    return `${resource.type} (${name})`
  }

  return name
}

/**
 * Enhance text by replacing resource hashes with readable names
 * Matches patterns like "res_abc123def4" and replaces them
 */
export function enhanceTextWithResourceNames(
  text: string,
  mapping: ResourceMapping
): string {
  if (!text) return text

  // Match resource hash pattern: res_[10 hex chars]
  const hashPattern = /res_[0-9a-f]{10}/g

  return text.replace(hashPattern, (hash) => {
    const resource = mapping[hash]
    if (!resource) {
      return hash
    }

    const name = extractResourceName(resource.address)
    // Format as: resource_type (name) [res_hash]
    return `${resource.type} (${name})`
  })
}
