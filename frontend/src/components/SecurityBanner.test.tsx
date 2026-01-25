import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import SecurityBanner from './SecurityBanner'

describe('SecurityBanner', () => {
    it('renders correctly for terraform mode', () => {
        render(<SecurityBanner type="terraform" />)
        expect(screen.getByText('Security-First Design')).toBeInTheDocument()
        expect(screen.getByText(/Terraform plan/)).toBeInTheDocument()
        expect(screen.getByText(/Resource names/)).toBeInTheDocument()
    })

    it('renders correctly for iam mode', () => {
        render(<SecurityBanner type="iam" />)
        expect(screen.getByText('Privacy-First Analysis')).toBeInTheDocument()
        expect(screen.getByText(/IAM policy/)).toBeInTheDocument()
        expect(screen.getByText(/ARNs and Account IDs/)).toBeInTheDocument()
    })
})
