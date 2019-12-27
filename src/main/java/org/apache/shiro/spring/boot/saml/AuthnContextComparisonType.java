/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.saml;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public enum AuthnContextComparisonType {

	/** Exact，精准模式，必须满足当前方式才能通过验证； */
	exact,
	/** Minimum，最少策略，满足这个方式或者比它更安全方式就通过验证；*/
	minimum,
	/** Maximum，最多策略，需要满足安全性最强的方式才能通过认证；*/
	maximum,
	/** Better，更优策略，需要满足比这个方式更为安全的方式才能通过验证；*/
	better;
	
}
