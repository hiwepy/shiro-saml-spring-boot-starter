/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.apache.shiro.spring.boot;

@Provider
public class ShiroAnnotationResourceFilter implements ContainerRequestFilter {

    private static final Map, AuthorizingAnnotationHandler> ANNOTATION_MAP = new HashMap, AuthorizingAnnotationHandler>();

    @Context
    private ResourceInfo resourceInfo;

    public ShiroAnnotationResourceFilter() {
        ANNOTATION_MAP.put(RequiresPermissions.class,
                new PermissionAnnotationHandler());
        ANNOTATION_MAP.put(RequiresRoles.class, new RoleAnnotationHandler());
        ANNOTATION_MAP.put(RequiresUser.class, new UserAnnotationHandler());
        ANNOTATION_MAP.put(RequiresGuest.class, new GuestAnnotationHandler());
        ANNOTATION_MAP.put(RequiresAuthentication.class,
                new AuthenticatedAnnotationHandler());
    }

    public void filter(ContainerRequestContext context) throws IOException {

        Class resourceClass = resourceInfo.getResourceClass();
        if (resourceClass != null) {
            Annotation annotation = fetchAnnotation(resourceClass
                    .getAnnotations());
            if (annotation != null) {
                ANNOTATION_MAP.get(annotation.annotationType())
                        .assertAuthorized(annotation);
            }
        }

        Method method = resourceInfo.getResourceMethod();
        if (method != null) {
            Annotation annotation = fetchAnnotation(method.getAnnotations());
            if (annotation != null) {
                ANNOTATION_MAP.get(annotation.annotationType())
                        .assertAuthorized(annotation);
            }
        }
    }

    private static Annotation fetchAnnotation(Annotation[] annotations) {
        for (Annotation annotation : annotations) {
            if (ANNOTATION_MAP.keySet().contains(annotation.annotationType())) {
                return annotation;
            }
        }
        return null;
    }
}