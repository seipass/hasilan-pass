package org.hasilan.pass

/** One explicit policy point shared by the activity and unit tests. */
internal object VaultLifecyclePolicy {
  /** A vault must not survive loss of foreground visibility, including configuration changes. */
  fun locksOnStop(): Boolean = true
}
