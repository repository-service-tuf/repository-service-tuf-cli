# Ceremony

Ceremony Metadata Management

$ `kaprien ceremony`

## Commands

### `start`

### Flow

```mermaid
    flowchart TD
    start --> overview
    overview --> start_ceremony{start ceremony?}
    start_ceremony-->|y| skip_continue_step_1{Step1 Skip/Continue}
    start_ceremony-->|n| End
    skip_continue_step_1 -->|continue| number_keys
    skip_continue_step_1 -->|skip| step_2[Step 2: Load/validate keys]

    subgraph step_1 [Step 1: Keys & Thresholds]
    define_keys_thresholds -->|root,targets,snapshot,timestamp,bin,bins| number_keys[Number of Keys:]
    number_keys --> role_threshold[Role Threshold:]
    end
    role_threshold -.->|next role| define_keys_thresholds
    role_threshold --> |finished| read_step_2[Ready to laod/validate keys]
    read_step_2 -->|y| step_2
    read_step_2 -->|n| End
    step_2 --> key_path[Key path: ]
    key_path --> key_password[Password: ]
    key_password --> key_verified{Verified?}
    key_verified --> verified
    key_verified --> failed
    verified -.->|next role| key_path
    failed --> try_again{Try again?}
    try_again -->|y| key_path
    try_again -->|n| End
    verified -->|finished| step_3[Step 3: Validate information]
    step_3 -->|root,targets,snapshot,timestamo,bin,bins| show_role_info[Show role information]
    show_role_info --> is_role_correct{is correct?}
    is_role_correct -.->|y, next role| step_3
    is_role_correct -->|n| number_keys
    is_role_correct --> |finished| bootstrap_metadata[Bootstrap Metadata]



