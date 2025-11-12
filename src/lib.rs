use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

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
        seeds = [b"manifest", creator.key().as_ref(), cid.as_bytes()],
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
        seeds = [b"attestation", validator.key().as_ref(), manifest.key().as_ref()],
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
pub struct RegisterValidator<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 1 + 8,  // discriminator + authority + active + registered_at
        seeds = [b"validator", authority.key().as_ref()],
        bump
    )]
    pub validator: Account<'info, Validator>,
    #[account(mut)]
    pub state: Account<'info, ProgramState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
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

#[error_code]
pub enum ErrorCode {
    #[msg("Validator is not active")]
    ValidatorNotActive,
    #[msg("Invalid confidence value")]
    InvalidConfidence,
    #[msg("Insufficient attestations for finalization")]
    InsufficientAttestations,
}