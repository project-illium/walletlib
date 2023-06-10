// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import "go.uber.org/zap"

var log = zap.S()

func UpdateLogger(logger *zap.Logger) {
	zap.ReplaceGlobals(logger)
	log = zap.S()
}
