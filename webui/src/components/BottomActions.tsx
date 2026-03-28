/**
 * Copyright 2025 Magic Mount-rs Authors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { ParentProps } from "solid-js";

import "./BottomActions.css";

export default (props: ParentProps) => (
  <div class="bottom-actions-root">{props.children}</div>
);
