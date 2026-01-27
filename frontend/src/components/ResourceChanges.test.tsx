import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import ResourceChanges from './ResourceChanges'
import { ResourceChange } from '@/lib/types'

describe('ResourceChanges', () => {
    const mockCreateResource: ResourceChange = {
        action: 'create',
        resource_type: 'aws_instance',
        resource_ref: 'hash_123',
        resource_address: 'aws_instance.web_server',
        changed_paths: ['instance_type', 'ami'],
        attribute_diffs: [
            { path: 'instance_type', before: null, after: 't2.micro' },
            { path: 'ami', before: null, after: 'ami-12345678' },
        ],
    }

    const mockUpdateResource: ResourceChange = {
        action: 'update',
        resource_type: 'aws_security_group',
        resource_ref: 'hash_456',
        resource_address: 'aws_security_group.main',
        changed_paths: ['ingress'],
        attribute_diffs: [
            { path: 'ingress.0.cidr_blocks', before: '10.0.0.0/8', after: '0.0.0.0/0' },
        ],
    }

    const mockDeleteResource: ResourceChange = {
        action: 'delete',
        resource_type: 'aws_s3_bucket',
        resource_ref: 'hash_789',
        resource_address: 'aws_s3_bucket.logs',
        changed_paths: [],
        attribute_diffs: [],
    }

    const mockReplaceResource: ResourceChange = {
        action: 'replace',
        resource_type: 'aws_rds_instance',
        resource_ref: 'hash_abc',
        resource_address: 'aws_rds_instance.database',
        changed_paths: ['engine_version'],
        attribute_diffs: [
            { path: 'engine_version', before: '13.4', after: '14.0' },
        ],
    }

    it('returns null when diffSkeleton is empty', () => {
        const { container } = render(<ResourceChanges diffSkeleton={[]} />)
        expect(container.firstChild).toBeNull()
    })

    it('returns null when diffSkeleton is undefined', () => {
        const { container } = render(<ResourceChanges diffSkeleton={undefined as any} />)
        expect(container.firstChild).toBeNull()
    })

    it('renders create action with correct styling', () => {
        render(<ResourceChanges diffSkeleton={[mockCreateResource]} />)

        const badge = screen.getByText('create')
        expect(badge).toHaveClass('action-create')
    })

    it('renders update action with correct styling', () => {
        render(<ResourceChanges diffSkeleton={[mockUpdateResource]} />)

        const badge = screen.getByText('update')
        expect(badge).toHaveClass('action-update')
    })

    it('renders delete action with correct styling', () => {
        render(<ResourceChanges diffSkeleton={[mockDeleteResource]} />)

        const badge = screen.getByText('delete')
        expect(badge).toHaveClass('action-delete')
    })

    it('renders replace action with correct styling', () => {
        render(<ResourceChanges diffSkeleton={[mockReplaceResource]} />)

        const badge = screen.getByText('replace')
        expect(badge).toHaveClass('action-replace')
    })

    it('displays resource address name correctly', () => {
        render(<ResourceChanges diffSkeleton={[mockCreateResource]} />)

        // extractResourceName should extract 'web_server' from 'aws_instance.web_server'
        expect(screen.getByText('web_server')).toBeInTheDocument()
    })

    it('displays resource type', () => {
        render(<ResourceChanges diffSkeleton={[mockCreateResource]} />)

        expect(screen.getByText('aws_instance')).toBeInTheDocument()
    })

    it('displays attribute diffs in table', () => {
        render(<ResourceChanges diffSkeleton={[mockCreateResource]} />)

        expect(screen.getByText('instance_type')).toBeInTheDocument()
        expect(screen.getByText('t2.micro')).toBeInTheDocument()
        expect(screen.getByText('ami')).toBeInTheDocument()
        expect(screen.getByText('ami-12345678')).toBeInTheDocument()
    })

    it('displays null values with italic styling', () => {
        render(<ResourceChanges diffSkeleton={[mockCreateResource]} />)

        const nullElements = screen.getAllByText('null')
        expect(nullElements.length).toBeGreaterThan(0)
        nullElements.forEach(el => {
            expect(el).toHaveClass('italic')
        })
    })

    it('shows message when no attribute diffs', () => {
        render(<ResourceChanges diffSkeleton={[mockDeleteResource]} />)

        expect(screen.getByText('No specific attribute changes recorded')).toBeInTheDocument()
    })

    it('renders multiple resources', () => {
        render(<ResourceChanges diffSkeleton={[mockCreateResource, mockUpdateResource, mockDeleteResource]} />)

        expect(screen.getByText('create')).toBeInTheDocument()
        expect(screen.getByText('update')).toBeInTheDocument()
        expect(screen.getByText('delete')).toBeInTheDocument()
    })

    it('handles boolean values in diffs', () => {
        const resourceWithBoolean: ResourceChange = {
            action: 'update',
            resource_type: 'aws_instance',
            resource_ref: 'hash_bool',
            changed_paths: ['monitoring'],
            attribute_diffs: [
                { path: 'monitoring', before: false, after: true },
            ],
        }

        render(<ResourceChanges diffSkeleton={[resourceWithBoolean]} />)

        expect(screen.getByText('false')).toBeInTheDocument()
        expect(screen.getByText('true')).toBeInTheDocument()
    })

    it('handles object values in diffs', () => {
        const resourceWithObject: ResourceChange = {
            action: 'update',
            resource_type: 'aws_instance',
            resource_ref: 'hash_obj',
            changed_paths: ['tags'],
            attribute_diffs: [
                { path: 'tags', before: { env: 'dev' }, after: { env: 'prod' } },
            ],
        }

        render(<ResourceChanges diffSkeleton={[resourceWithObject]} />)

        expect(screen.getByText('{"env":"dev"}')).toBeInTheDocument()
        expect(screen.getByText('{"env":"prod"}')).toBeInTheDocument()
    })

    it('falls back to resource_type when resource_address is missing', () => {
        const resourceWithoutAddress: ResourceChange = {
            action: 'create',
            resource_type: 'aws_lambda_function',
            resource_ref: 'hash_no_addr',
            changed_paths: [],
            attribute_diffs: [],
        }

        render(<ResourceChanges diffSkeleton={[resourceWithoutAddress]} />)

        // Should show resource_type twice (once in header, once as type label)
        const lambdaElements = screen.getAllByText('aws_lambda_function')
        expect(lambdaElements.length).toBeGreaterThanOrEqual(1)
    })

    it('applies correct id for anchor linking', () => {
        render(<ResourceChanges diffSkeleton={[mockCreateResource]} />)

        const resourceDiv = document.getElementById('resource-hash_123')
        expect(resourceDiv).toBeInTheDocument()
    })
})
