/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.source.formatter.check;

import com.liferay.petra.string.CharPool;
import com.liferay.petra.string.StringPool;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Lucas Miranda
 */
public class JavaSecretComparisonCheck extends BaseFileCheck {

	@Override
	public boolean isLiferaySourceCheck() {
		return true;
	}

	@Override
	protected String doProcess(
		String fileName, String absolutePath, String content) {

		if (absolutePath.contains("/modules/third-party/") ||
			absolutePath.contains("/modules/util/") ||
			absolutePath.contains("/test/") ||
			absolutePath.contains("/testIntegration/") ||
			fileName.endsWith("BaseLDAPExportModelListener.java") ||
			fileName.endsWith("PwdGenerator.java") ||
			fileName.endsWith("SharepointUtil.java")) {

			return content;
		}

		Matcher matcher = _equalsPattern.matcher(content);

		while (matcher.find()) {
			String arguments = _getArguments(content, matcher.end() - 1);

			if (arguments == null) {
				continue;
			}

			String leftOperand = matcher.group(1);
			String rightOperand = arguments;

			if (leftOperand.equals("Objects")) {
				int index = _getCommaIndex(arguments);

				if (index == -1) {
					continue;
				}

				leftOperand = arguments.substring(0, index);
				rightOperand = arguments.substring(index + 1);
			}

			if (_isSecretComparison(leftOperand, rightOperand)) {
				addMessage(
					fileName,
					"Use MessageDigest.isEqual to compare secrets, see " +
						"LPD-93281",
					getLineNumber(content, matcher.start()));
			}
		}

		return content;
	}

	private String _getArguments(String content, int pos) {
		int depth = 0;

		for (int i = pos; i < content.length(); i++) {
			char c = content.charAt(i);

			if (c == CharPool.QUOTE) {
				i = _skipQuotedText(content, i);

				if (i == -1) {
					return null;
				}

				continue;
			}

			if (c == CharPool.OPEN_PARENTHESIS) {
				depth++;
			}
			else if (c == CharPool.CLOSE_PARENTHESIS) {
				depth--;

				if (depth == 0) {
					return content.substring(pos + 1, i);
				}
			}
		}

		return null;
	}

	private int _getCommaIndex(String arguments) {
		int depth = 0;

		for (int i = 0; i < arguments.length(); i++) {
			char c = arguments.charAt(i);

			if (c == CharPool.QUOTE) {
				i = _skipQuotedText(arguments, i);

				if (i == -1) {
					return -1;
				}

				continue;
			}

			if (c == CharPool.OPEN_PARENTHESIS) {
				depth++;
			}
			else if (c == CharPool.CLOSE_PARENTHESIS) {
				depth--;
			}
			else if ((c == CharPool.COMMA) && (depth == 0)) {
				return i;
			}
		}

		return -1;
	}

	private String _getName(String operand) {
		operand = operand.trim();

		int index = operand.lastIndexOf(CharPool.PERIOD);

		if (index != -1) {
			operand = operand.substring(index + 1);
		}

		return operand;
	}

	private boolean _isConstant(String operand) {
		operand = operand.trim();

		if (operand.startsWith(StringPool.QUOTE)) {
			return true;
		}

		return _constantPattern.matcher(
			_getName(operand)
		).matches();
	}

	private boolean _isSecretComparison(
		String leftOperand, String rightOperand) {

		if (_isConstant(leftOperand) || _isConstant(rightOperand)) {
			return false;
		}

		if (!_isSecretName(leftOperand) && !_isSecretName(rightOperand)) {
			return false;
		}

		return true;
	}

	private boolean _isSecretName(String operand) {
		operand = operand.trim();

		if (operand.indexOf(CharPool.OPEN_PARENTHESIS) != -1) {
			return false;
		}

		String name = _getName(operand);

		if (_identifierPattern.matcher(
				name
			).matches()) {

			return false;
		}

		return _secretNamePattern.matcher(
			name
		).matches();
	}

	private int _skipQuotedText(String s, int pos) {
		for (int i = pos + 1; i < s.length(); i++) {
			char c = s.charAt(i);

			if (c == CharPool.BACK_SLASH) {
				i++;
			}
			else if (c == CharPool.QUOTE) {
				return i;
			}
		}

		return -1;
	}

	private static final Pattern _constantPattern = Pattern.compile(
		"_*[A-Z][A-Z0-9_]{2,}");
	private static final Pattern _equalsPattern = Pattern.compile(
		"\\b([\\w.]+)\\.equals\\s*\\(");
	private static final Pattern _identifierPattern = Pattern.compile(".*Ids?");
	private static final Pattern _secretNamePattern = Pattern.compile(
		"\\w*(?i:secret|token|password|apiKey|hmac|otp|nonce)\\w*");

}