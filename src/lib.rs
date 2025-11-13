use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

pub mod pda_seeds {
    pub const MANIFEST: &[u8] = b"manifest";
    pub const ATTESTATION: &[u8] = b"attestation";
    pub const VALIDATOR: &[u8] = b"validator";
    pub const GOVERNANCE: &[u8] = b"governance";
}

#[program]
pub mod neuro_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.authority = ctx.accounts.authority.key();
        state.validator_count = 0;
        Ok(())
    }

    pub fn init_manifest(ctx: Context<InitManifest>, cid: String, data: Vec<u8>) -> Result<()> {
        let manifest = &mut ctx.accounts.manifest;
        let clock = Clock::get()?;

        manifest.creator = ctx.accounts.creator.key();
        manifest.cid = cid.clone();
        manifest.data_hash = hash(&data).to_bytes();
        manifest.created_at = clock.unix_timestamp;
        manifest.finalized = false;
        manifest.attestation_count = 0;

        emit!(ManifestCreated {
            cid,
            creator: manifest.creator,
            data_hash: manifest.data_hash,
        });

        Ok(())
    }

    pub fn attest(ctx: Context<Attest>, confidence: u8) -> Result<()> {
        let attestation = &mut ctx.accounts.attestation;
        let manifest = &mut ctx.accounts.manifest;
        let validator = &ctx.accounts.validator;
        let clock = Clock::get()?;

        require!(validator.active, ErrorCode::ValidatorNotActive);
        require!(confidence <= 100, ErrorCode::InvalidConfidence);

        attestation.validator = ctx.accounts.validator.key();
        attestation.manifest = manifest.key();
        attestation.confidence = confidence;
        attestation.created_at = clock.unix_timestamp;

        manifest.attestation_count += 1;

        emit!(AttestationCreated {
            manifest: manifest.key(),
            validator: validator.key(),
            confidence,
        });

        Ok(())
    }

    pub fn finalize_manifest(ctx: Context<FinalizeManifest>) -> Result<()> {
        let manifest = &mut ctx.accounts.manifest;
        let state = &ctx.accounts.state;

        // Simple majority for now
        let required = (state.validator_count / 2) + 1;
        require!(manifest.attestation_count >= required, ErrorCode::InsufficientAttestations);

        manifest.finalized = true;

        emit!(ManifestFinalized {
            cid: manifest.cid.clone(),
            attestation_count: manifest.attestation_count,
        });

        Ok(())
    }

    pub fn reject_manifest(ctx: Context<RejectManifest>) -> Result<()> {
        let manifest = &mut ctx.accounts.manifest;
        
        require!(!manifest.finalized, ErrorCode::ManifestAlreadyFinalized);
        
        // Only creator can reject their own manifest
        require!(ctx.accounts.creator.key() == manifest.creator, ErrorCode::Unauthorized);

        // Close the account to recover rent
        manifest.close(ctx.accounts.creator.to_account_info())?;

        emit!(ManifestRejected {
            cid: manifest.cid.clone(),
        });

        Ok(())
    }

    pub fn register_validator(ctx: Context<RegisterValidator>) -> Result<()> {
        let validator = &mut ctx.accounts.validator;
        let state = &mut ctx.accounts.state;

        validator.authority = ctx.accounts.authority.key();
        validator.active = true;
        validator.registered_at = Clock::get()?.unix_timestamp;

        state.validator_count += 1;

        emit!(ValidatorRegistered {
            validator: validator.key(),
            authority: validator.authority,
        });

        Ok(())
    }

    pub fn update_validator(ctx: Context<UpdateValidator>, active: bool) -> Result<()> {
        let validator = &mut ctx.accounts.validator;
        
        require!(ctx.accounts.authority.key() == validator.authority, ErrorCode::Unauthorized);

        validator.active = active;

        emit!(ValidatorUpdated {
            validator: validator.key(),
            active,
        });

        Ok(())
    }

    pub fn init_governance(ctx: Context<InitGovernance>) -> Result<()> {
        let governance = &mut ctx.accounts.governance;
        
        governance.authority = ctx.accounts.authority.key();
        governance.proposal_count = 0;
        governance.total_stake = 0;
        governance.created_at = Clock::get()?.unix_timestamp;

        emit!(GovernanceInitialized {
            governance: governance.key(),
            authority: governance.authority,
        });

        Ok(())
    }

    pub fn update_governance(ctx: Context<UpdateGovernance>, new_authority: Pubkey) -> Result<()> {
        let governance = &mut ctx.accounts.governance;
        
        require!(ctx.accounts.authority.key() == governance.authority, ErrorCode::Unauthorized);

        governance.authority = new_authority;

        emit!(GovernanceUpdated {
            governance: governance.key(),
            new_authority,
        });

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8)]
    pub state: Account<'info, ProgramState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(cid: String)]
pub struct InitManifest<'info> {
    #[account(
        init,
        payer = creator,
        space = 8 + 32 + (4 + 64) + 32 + 8 + 1 + 8,  // discriminator + creator + cid + data_hash + created_at + finalized + attestation_count
        seeds = [pda_seeds::MANIFEST, creator.key().as_ref(), cid.as_bytes()],
        bump
    )]
    pub manifest: Account<'info, Manifest>,
    #[account(mut)]
    pub creator: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Attest<'info> {
    #[account(
        init,
        payer = validator_authority,
        space = 8 + 32 + 32 + 1 + 8,  // discriminator + validator + manifest + confidence + created_at
        seeds = [pda_seeds::ATTESTATION, validator.key().as_ref(), manifest.key().as_ref()],
        bump
    )]
    pub attestation: Account<'info, Attestation>,
    #[account(mut)]
    pub manifest: Account<'info, Manifest>,
    pub validator: Account<'info, Validator>,
    #[account(mut)]
    pub validator_authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FinalizeManifest<'info> {
    #[account(mut)]
    pub manifest: Account<'info, Manifest>,
    pub state: Account<'info, ProgramState>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct RejectManifest<'info> {
    #[account(mut, close = creator)]
    pub manifest: Account<'info, Manifest>,
    #[account(mut)]
    pub creator: Signer<'info>,
}

#[derive(Accounts)]
pub struct RegisterValidator<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 1 + 8,  // discriminator + authority + active + registered_at
        seeds = [pda_seeds::VALIDATOR, authority.key().as_ref()],
        bump
    )]
    pub validator: Account<'info, Validator>,
    #[account(mut)]
    pub state: Account<'info, ProgramState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateValidator<'info> {
    #[account(mut)]
    pub validator: Account<'info, Validator>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitGovernance<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 8 + 8,  // discriminator + authority + proposal_count + total_stake + created_at
        seeds = [pda_seeds::GOVERNANCE],
        bump
    )]
    pub governance: Account<'info, Governance>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateGovernance<'info> {
    #[account(mut)]
    pub governance: Account<'info, Governance>,
    pub authority: Signer<'info>,
}

#[account]
pub struct ProgramState {
    pub authority: Pubkey,
    pub validator_count: u64,
}

#[account]
pub struct Manifest {
    pub creator: Pubkey,
    pub cid: String,
    pub data_hash: [u8; 32],
    pub created_at: i64,
    pub finalized: bool,
    pub attestation_count: u64,
}

#[account]
pub struct Attestation {
    pub validator: Pubkey,
    pub manifest: Pubkey,
    pub confidence: u8,
    pub created_at: i64,
}

#[account]
pub struct Validator {
    pub authority: Pubkey,
    pub active: bool,
    pub registered_at: i64,
}

#[account]
pub struct Governance {
    pub authority: Pubkey,
    pub proposal_count: u64,
    pub total_stake: u64,
    pub created_at: i64,
}

#[event]
pub struct ManifestCreated {
    pub cid: String,
    pub creator: Pubkey,
    pub data_hash: [u8; 32],
}

#[event]
pub struct AttestationCreated {
    pub manifest: Pubkey,
    pub validator: Pubkey,
    pub confidence: u8,
}

#[event]
pub struct ManifestFinalized {
    pub cid: String,
    pub attestation_count: u64,
}

#[event]
pub struct ValidatorRegistered {
    pub validator: Pubkey,
    pub authority: Pubkey,
}

#[event]
pub struct ValidatorUpdated {
    pub validator: Pubkey,
    pub active: bool,
}

#[event]
pub struct GovernanceInitialized {
    pub governance: Pubkey,
    pub authority: Pubkey,
}

#[event]
pub struct GovernanceUpdated {
    pub governance: Pubkey,
    pub new_authority: Pubkey,
}

#[event]
pub struct ManifestRejected {
    pub cid: String,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Validator is not active")]
    ValidatorNotActive,
    #[msg("Invalid confidence value")]
    InvalidConfidence,
    #[msg("Insufficient attestations for finalization")]
    InsufficientAttestations,
    #[msg("Manifest is already finalized")]
    ManifestAlreadyFinalized,
    #[msg("Unauthorized operation")]
    Unauthorized,
}