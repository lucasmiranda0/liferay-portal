/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.osgi.service.tracker.collections.internal.map;

import com.liferay.osgi.service.tracker.collections.ServiceReferenceServiceTuple;
import com.liferay.osgi.service.tracker.collections.map.ServiceTrackerBucket;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.osgi.framework.Bundle;
import org.osgi.framework.ServiceReference;

/**
 * @author Manuele Castro
 */
public class MultiValueServiceTrackerBucketFactoryTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@Test
	public void testGetContent() {
		MultiValueServiceTrackerBucketFactory<Object, Object>
			multiValueServiceTrackerBucketFactory =
				new MultiValueServiceTrackerBucketFactory<>();

		ServiceTrackerBucket<Object, Object, List<Object>>
			serviceTrackerBucket =
				multiValueServiceTrackerBucketFactory.create();

		Object service = new Object();

		serviceTrackerBucket.store(
			new ServiceReferenceServiceTuple<>(
				new TestServiceReference(), service));

		List<List<Object>> contents = new ArrayList<>();

		serviceTrackerBucket.store(
			new ServiceReferenceServiceTuple<Object, Object>(
				new TestServiceReference(), new Object()) {

				@Override
				public Object getService() {
					contents.add(serviceTrackerBucket.getContent());

					return super.getService();
				}

			});

		Assert.assertEquals(
			Collections.singletonList(Collections.singletonList(service)),
			contents);
	}

	private static class TestServiceReference
		implements ServiceReference<Object> {

		@Override
		public int compareTo(Object object) {
			return 0;
		}

		@Override
		public Bundle getBundle() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Object getProperty(String key) {
			throw new UnsupportedOperationException();
		}

		@Override
		public String[] getPropertyKeys() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Bundle[] getUsingBundles() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isAssignableTo(Bundle bundle, String className) {
			throw new UnsupportedOperationException();
		}

	}

}